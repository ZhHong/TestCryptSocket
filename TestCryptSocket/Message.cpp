#include "Message.h"


Message::Message()
{
}


Message::~Message()
{
}

void Message::setMessage(std::vector<unsigned int> orig_data) {
	//set orignal data
	int len = orig_data.size();
	int i;
	for (i = 0; i < len; i++) {
		Message::original.push_back(orig_data[i]);
	}
}
void Message::getOriginalStr() {

}