#include "stdafx.h"

class offset_signature {
public:
	std::string _name;
	std::string _sigs;
	std::string _sub_base;
	std::string _read;
	std::string _additional;
	std::string _offset;
	//===========================
	std::vector<std::string> sigs;
	bool sub_base;
	bool read;
	int32_t additional;
	uint32_t offset;
};

class CObject {
public:
	std::string name;
	std::string offset;
	std::string type;
};