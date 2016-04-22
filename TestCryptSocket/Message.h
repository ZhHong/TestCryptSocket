#ifndef _MESSAGEH_
#define _MESSAGEH_
#define MAX_MESSAGE_SZ 1024
#include <vector>
class Message
{
typedef struct
{
	int data_len;
	char data[0];
}buffer;
public:
	Message();
	~Message();
	void getOriginalStr();
	void getBase64Str();
	void getHexStr();
	void setMessage(std::vector<unsigned int>);
	void resetMessage();
	void newMessage();
private:
	std::vector<unsigned int> original;
	int msgType;
	int msgLength;
};
#endif

