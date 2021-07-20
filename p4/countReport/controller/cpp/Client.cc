#include <fstream>
#include <unordered_map>

#include "gen-cpp/RunTimeEnvironment.h"
#include "lib/json.hpp"

#include "Client.h"
#include "StatHeader.h"
#include "utils.h"

using namespace nlohmann;
using namespace std;

#define VF_NUMBER_REG_NAME string("vf_number")


const string global_params [] = {string(P_SRC_V6), string(P_SRC_V4),
				 string(P_SRC_PREFIX_LEN), string(P_DST_V4),
				 string(P_DST_V6), string(P_DST_PREFIX_LEN),
				 string(P_SRC_PORT), string(P_DST_PORT),
				 string(P_TCP), string(P_UDP), string("")};

const unordered_multimap<string, string> match_param = {
	{string(P_SRC_V6), string(M_SRC_V6)},
	{string(P_SRC_V4), string(M_SRC_V4)},
	{string(P_SRC_PREFIX_LEN), string(M6_SRC_PREFIX_LEN)},
	{string(P_SRC_PREFIX_LEN), string(M4_SRC_PREFIX_LEN)},
	{string(P_DST_V6), string(M_DST_V6)},
	{string(P_DST_V4), string(M_DST_V4)},
	{string(P_DST_PREFIX_LEN), string(M6_DST_PREFIX_LEN)},
	{string(P_DST_PREFIX_LEN), string(M4_DST_PREFIX_LEN)},
	{string(P_SRC_PORT), string(MT_SRC_PORT)},
	{string(P_SRC_PORT), string(MU_SRC_PORT)},
	{string(P_DST_PORT), string(MT_DST_PORT)},
	{string(P_DST_PORT), string(MU_DST_PORT)},
	{string(P_TCP), string(M_TCP)},
	{string(P_UDP), string(M_UDP)}
};

const string table_names [4] = {
	string("flow_ip6_tcp_tbl"),
	string("flow_ip6_udp_tbl"),
	string("flow_ip4_tcp_tbl"),
	string("flow_ip4_udp_tbl")
};


uint32_t idx = 1; /* FIXME Handle holes in case of removals => this is too simple */


static void fill_json_rule(json &default_rule, json &action, const json &match)
{
	action["idx"] = {{"value", idx}};
	idx++;
	string excluded_transport = "";

	string name = string(*global_params);
	for (int i = 0; name.length(); i++, name = string(global_params[i])) {

		/* Map match values to param values */
		decltype(match_param.equal_range("")) match_values;
		match_values = match_param.equal_range(name);
		auto param = match.end();

		for (auto it = match_values.first;
		     it != match_values.second; it++) {
			param = match.find(it->second);
			if (param != match.end())
				break;
		}

		if (param == match.end()) {
			/* tcp.valid and udp.valid cannot be matched at the same time*/
			if (name == excluded_transport)
				action[name] = {"value", "0x0"};
			else
				action[name] = default_rule[name];
		} else {
			json param_mod (*param);
			if (param_mod["value"].get<string>() == "valid") {
				param_mod["value"] = "0x1";
				excluded_transport = name == string(P_UDP)
					? string(P_UDP) : string(P_TCP);
				action[excluded_transport] = {"value", "0x0"};
			}
			action[name] = param_mod;
		}
	}
}

static void fill_default_rule(json &action, int udp, int tcp)
{
	action["data"] = {
		{"idx", {{"value", idx++}}},
		{P_SRC_V6, {{"value", "::"}}},
		{P_SRC_V4, {{"value", "0.0.0.0" }}},
		{P_SRC_PREFIX_LEN, {{"value", "8'0x0"}}},
		{P_DST_V6, {{"value", "::"}}},
		{P_DST_V4, {{"value", "0.0.0.0" }}},
		{P_DST_PREFIX_LEN, {{"value", "8'0x0"}}},
		{P_SRC_PORT, {{"value", "0x0"}}},
		{P_DST_PORT, {{"value", "0x0"}}},
		{P_TCP, {{"value", tcp}}},
		{P_UDP, {{"value", udp}}}
	};

}

int Client::design_reconfig(const string &pif_config_json_path,
			    vector<StatFlow> &flows, uint32_t max_vfs)
{
	ifstream in_stream(pif_config_json_path);
	json pif_config_json;
	in_stream >> pif_config_json;

	try {
		for (const auto &table_name : table_names) {
			json &table = pif_config_json["tables"][table_name];
			json &default_rule = table["default_rule"];

			/* Identifies protocols */
			int tcp = table_name.find("tcp") != string::npos;
			int udp = !tcp;
			int ipv4 = table_name.find("ip4") != string::npos;
			int ipv6 = !ipv4;

			if (default_rule.find("action") == default_rule.end()) {
				default_rule["action"] = {};
				default_rule["action"]["type"] = "fwd_act";

				fill_default_rule(default_rule["action"],
						  udp, tcp);
			}

			json &rules = table["rules"];
			StatFlow flow = StatFlow();
			if (flow.init(default_rule["action"]["data"],
				      ipv4, ipv6, tcp, udp)) {
				return -1;
			}
			flows.push_back(flow);

			for (auto &rule : rules) {
				if (rule.find("action") == rule.end()) {
					rule["priority"] = 1;
					rule["action"] = {{"type", "fwd_act"},
							 {"data", {} }};
					fill_json_rule(default_rule["action"]["data"],
						       rule["action"]["data"],
						       rule["match"]);
				}

				if (flow.init(rule["action"]["data"],
					      ipv4, ipv6, tcp, udp))
					return -1;
				flows.push_back(flow);
			}
		}

		/* Add statistics shortcut */
		pif_config_json["tables"]["mac_tbl"] = {
			{"default_rule", {
						 {"name", "default"},
						 {"action", {
								    {"type", "set_nexthop"},
								    {"data", {{"port", {{"value", "v0.2"}}}}}
							    }
						 }
					 }
			}
		};

		pif_config_json["tables"]["controller_cmd_tbl"] = {
			{"default_rule", {
						 {"name", "default"},
						 {"action", {
								    {"type", "controller_clock"},
								    {"data", {{"port", {{"value", "v0.1"}}}}}
							    }
						 }
					 }
			}
		};

		pif_config_json["tables"]["checksum_recompute"] = {
			{"default_rule", {
						 {"name", "default"},
						 {"action", {
								    {"type", "trigger_checksum_update"}
							    }
						 }
					 }
			}
		};

		pif_config_json["tables"]["ecmp_tbl"] = {{"rules", json::array()}};
		json &ecmp_tbl = pif_config_json["tables"]["ecmp_tbl"]["rules"];
		/* The 2 first ones are reserved for input and controller commands */
		uint32_t ifindex = 2;
		for (int i = 0; ifindex < max_vfs; i++, ifindex++) {
			string ifname;
			string nic_ifname;
			vfname(ifindex, ifname);
			nic_vfname(ifindex, nic_ifname);
			ecmp_tbl.push_back({
				{"name", ifname},
				{"action", {
						{"type", "set_nexthop"},
						{"data", {{"port", {{"value", nic_ifname}}}}}
					   }
				},
				{"match", {
						{"flow_meta.ecmp_hash_value", {{"value", i}}}
					  }
				}
			});
		}
	} catch (out_of_range &e) {
		cerr << "Out of range error: " << e.what() << endl;
		return -1;
	} catch (domain_error &e)  {
		cerr << "Domain error: " << e.what() << endl;
		return -1;
	}

	string json_str = pif_config_json.dump();
	RteReturn rte;
	this->RunTimeEnvironmentClient::design_reconfig(rte, json_str);

	return !(rte.value == 0);
}

int Client::retrieve_stats(vector<StatFlow> &flows)
{
	P4CounterReturn ret;
	this->p4_counter_retrieve(ret, this->pktcnt_index);
	if (ret.count < 0) {
		cerr << "Cannot retrieve the counters" << endl;
		return -1;
	}

	uint64_t *counters = (uint64_t *) ret.data.data();
	for(StatFlow &flow : flows) {
		if (((int) flow.idx) >= ret.count) {
			cerr << "Out of bounds counter index" << endl;
			return -1;
		}
		flow.fl_pktcnt = counters[flow.idx];
	}
	return 0;
}

int Client::info_fetching()
{
	bool found = false;
	vector<P4CounterDesc> desc_list;
	this->p4_counter_list_all(desc_list);
	for (auto &cnt_desc : desc_list) {
		if (cnt_desc.name == "fl_count_packets") {
			found = true;
			this->pktcnt_index = cnt_desc.id;
			break;
		}
		idx++;
	}
	return !found;
}

