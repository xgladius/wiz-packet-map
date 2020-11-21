#pragma once
#include <Windows.h>
#include <string>
#include <vector>
#include "wiz_wad.h"
#include "rapidxml.hpp"
#include <map>

using namespace rapidxml;

struct field {
	std::string name;
	std::string type;
	std::string value;
};

struct xml_message {
	std::string msg_name;
	std::string msg_description;
	std::string msg_handler;
	std::string msg_access_level;
	int msg_order;
	std::vector<field> params;
};

struct protocol_info {
	byte service_id;
	std::string protocol_type;
	int protocol_version;
	std::string protocol_description;
	std::vector<xml_message> messages;
};

xml_message get_msg_from_xml(xml_node<>* node)
{
	xml_message ret;
	const std::string node_name = node->name();
	if (node_name != "RECORD")
	{
		printf("Expected <RECORD> node but got <%s>.\n", node->name());
	}

	for (auto* field_node = node->first_node();
		field_node; field_node = field_node->next_sibling())
	{
		if (field_node->type() != node_element)
			continue;

		const auto type = field_node->first_attribute("TYPE");

		if (!type)
		{
			printf("Type required but not found on %s??\n", field_node->name());
			continue;
		}

		const auto name = std::string(field_node->name());

		if (name == "_MsgName")
		{
			ret.msg_name = field_node->value();
			continue;
		}

		if (name == "_MsgDescription")
		{
			ret.msg_description = field_node->value();
			continue;
		}

		if (name == "_MsgHandler")
		{
			ret.msg_handler = field_node->value();
			continue;
		}

		if (name == "_MsgOrder")
		{
			ret.msg_order = reinterpret_cast<int>(field_node->value());
			continue;
		}

		if (name == "_MsgAccessLvl")
		{
			ret.msg_access_level = field_node->value();
			continue;
		}
		
		ret.params.push_back({ field_node->name(), std::string(type->value()) });
	}
	return ret;
}

int has_msg_order(xml_node<>* node)
{
	for (auto* field_node = node->first_node();
		field_node; field_node = field_node->next_sibling())
	{
		if (field_node->type() != node_element)
			continue;

		const auto name = std::string(field_node->name());

		if (name == "_MsgOrder")
			return atoi(field_node->value());
	}
	return 0;
}

std::vector<protocol_info> get_protocols() {
	std::vector<protocol_info> protocols;
	std::vector<file_dat> messages;
	get_wad("Messages.xml", ".xml", messages);
	for (auto message : messages) {
		
		std::map<std::string, xml_message> msgs;
		
		message.file.push_back(0x00);
		const auto data = reinterpret_cast<char*>(message.file.data());
		xml_document<> doc;
		try
		{
			doc.parse<0>(data);
		}
		catch (parse_error & e)
		{
			printf("Failed to parse\n");
			return {};
		}

		auto has_record_order = false;

		auto* root = doc.first_node();
		
		for (auto* node = root->first_node();
			node; node = node->next_sibling())
		{
			auto* record_node = node->first_node();
			if (!record_node)
				continue;
			const auto record_order = has_msg_order(record_node);
			if (record_order > 0)
				has_record_order = true;
		}

		std::vector<xml_message> sorted_messages;
		if (has_record_order)
			sorted_messages.resize(254);
		

		for (auto* node = root->first_node();
			node; node = node->next_sibling())
		{			
			auto* record_node = node->first_node();
			if (!record_node)
				continue;

			auto record = get_msg_from_xml(record_node);

			if (has_record_order)
			{
				sorted_messages[has_msg_order(record_node)] = record;
			}
			else 
			{
				msgs.insert(std::pair<std::string, xml_message>(record.msg_name, record));
			}
		}

		if (!has_record_order) {
			for (auto it = msgs.begin();
				it != msgs.end(); ++it)
			{
				sorted_messages.push_back(it->second);
			}
		}

		protocol_info message_module =
		{
			static_cast<uint8_t>(atoi(root->first_node()->first_node()->first_node("ServiceID")->value())),
			std::string(root->first_node()->first_node()->first_node("ProtocolType")->value()),
			atoi(root->first_node()->first_node()->first_node("ProtocolVersion")->value()),
			std::string(root->first_node()->first_node()->first_node("ProtocolDescription")->value()),
			sorted_messages
		};

		protocols.push_back(message_module);
	}
	return protocols;
}