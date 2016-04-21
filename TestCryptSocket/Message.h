#ifndef _MESSAGEH_
#define _MESSAGEH_
#define MAX_MESSAGE_SZ 1024
#include <vector>
class Message
{
public:
	Message();
	~Message();
	void getOriginalStr();
	void getBase64Str();
	void getHexStr();
	void setMessage(std::vector<unsigned int>);
	void resetMessage();
private:
	std::vector<unsigned int> original;
	int msgType;
	int msgLength;
};
#endif

