#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

// 使用 238 * 255 个线程（会OOM，并且容易被判断为网络攻击）
//#define USE_LARGE_MEM

#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <thread>
#include <memory>
#include <chrono>
#include <mutex>
#include <stdexcept>
#include <cstdlib>
#include <cstring>

#include "json/json.h"

#if defined(_WIN32)
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
// Need to link with Ws2_32.lib, Mswsock.lib, and Advapi32.lib
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

#define Exit(msg) \
 do { std::cerr << "ERROR: " << msg << std::endl; exit(EXIT_FAILURE); } while (0)
#define Free(ptr) \
 free(ptr); (ptr) = NULL
#define LOGD(msg) \
 std::cout << "DEBUG: " << msg << std::endl
#define LOGI(msg) \
 std::cout << "INFO: " << msg << std::endl
#define LOGE(msg) \
 std::cerr << "ERROR: " << msg << std::endl
#define LOGW(msg) \
 std::cerr << "WARNING: " << msg << std::endl
#else
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define SOCKET int
#define ZeroMemory bzero
#define INVALID_SOCKET (-1)
#define WSAGetLastError() strerror(errno)
#define WSACleanup()
#define SOCKET_ERROR (-1)
#define closesocket close
//#define FD_ZERO FDZERO
#define Exit(msg) \
 do { std::cerr << "\033[31mERROR: " << msg << "\033[0m" << std::endl; exit(EXIT_FAILURE); } while (0)
#define Free(ptr) \
 free(ptr); (ptr) = NULL
#define LOGD(msg) \
 std::cout << "DEBUG: " << msg << std::endl
#define LOGI(msg) \
 std::cout << "\033[1mINFO: " << msg << "\033[0m" << std::endl
#define LOGE(msg) \
 std::cerr << "\033[31;1;4mERROR: " << msg << "\033[0m" << std::endl
#define LOGW(msg) \
 std::cerr << "\033[33;1mWARNING: " << msg << "\033[0m" << std::endl
#endif

typedef unsigned char Byte;
static std::mutex mtx;

class TcpStreamBuf : public std::streambuf {
public:
	TcpStreamBuf(SOCKET socket, size_t buf_size);
	~TcpStreamBuf();

	int overflow(int c);  // 字符 c 是调用 overflow 时当前的字符
	int sync();           // 将buffer中的内容刷新到外部设备，不管缓冲区是否满
	int underflow();

private:
	const size_t buf_size_;
	const SOCKET socket_;
	char* pbuf_; // 输出缓冲区
	char* gbuf_; // 输入缓冲区
};

TcpStreamBuf::TcpStreamBuf(const SOCKET socket, const size_t buf_size) :
	buf_size_(buf_size), socket_(socket) {
	if (buf_size_ <= 0) throw std::overflow_error("buf_size must > 0");
	pbuf_ = new char[buf_size_];

	setp(pbuf_, pbuf_ + buf_size_); // set the pointers for output buf

	gbuf_ = new char[buf_size_];
	setg(gbuf_, gbuf_, gbuf_);
}

TcpStreamBuf::~TcpStreamBuf() {
	if (pbuf_ != nullptr) {
		delete[] pbuf_;
		pbuf_ = nullptr;
	}

	if (gbuf_ != nullptr) {
		delete[] gbuf_;
		gbuf_ = nullptr;
	}
}

// flush the data to the socket
int TcpStreamBuf::sync() {
	int sent = 0;
	int total = pptr() - pbase();  // data that can be flushed
	while (sent < total) {
		int ret = send(socket_, pbase() + sent, total - sent, 0);
		if (ret > 0) sent += ret;
		else {
			return -1;
		}
	}
	setp(pbase(), pbase() + buf_size_);  // reset the buffer
	pbump(0);  // reset pptr to buffer head

	return 0;
}

int TcpStreamBuf::overflow(const int c) {
	if (-1 == sync()) {
		return traits_type::eof();
	}
	else {
		// put c into buffer after successful sync
		if (!traits_type::eq_int_type(c, traits_type::eof())) {
			sputc(traits_type::to_char_type(c));
		}

		//return eq_int_type(c, eof()) ? eof():c;
		return traits_type::not_eof(c);
	}
}

int TcpStreamBuf::underflow() {
	int ret = recv(socket_, eback(), buf_size_, 0);
	if (ret > 0) {
		setg(eback(), eback(), eback() + ret);
		return traits_type::to_int_type(*gptr());
	}
	else {
		return traits_type::eof();
	}
}

class BasicTcpStream : public std::iostream {
public:
	BasicTcpStream(const SOCKET socket, const size_t buf_size) :
		std::iostream(new TcpStreamBuf(socket, buf_size)),
		socket_(socket), buf_size_(buf_size) {
	}
	~BasicTcpStream() {
		delete rdbuf();
	}

private:
	int socket_;
	const size_t buf_size_;
};

int readVarInt(std::istream& stream) {
	int i = 0;
	int j = 0;
	while (true) {
		int k = stream.get();
		if (k == (int)std::istream::traits_type::eof()) return -1;
		i |= (k & 0x7F) << j++ * 7;
		if (j > 5) throw std::runtime_error("VarInt too big");
		if ((k & 0x80) != 128) break;
	}
	return i;
}

void writeVarInt(std::ostream& stream, int paramInt) {
	while (true) {
		if ((paramInt & 0xFFFFFF80) == 0) {
			stream.put((char)paramInt);
			return;
		}

		stream.put(paramInt & 0x7F | 0x80);
		paramInt >>= 7;
	}
}

Json::Value status(const sockaddr_in& addr) {
	int iResult;

	SOCKET ConnectSocket = INVALID_SOCKET;
	// 创建用于连接到服务器的SOCKET
	ConnectSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (ConnectSocket == INVALID_SOCKET) {
		LOGE("Error at socket(): " << strerror(errno));
		throw std::runtime_error("Error at socket()");
	}

	// 设置连接超时
	// 设置非阻塞
#if defined(_WIN32)
	iResult = 1;
	ioctlsocket(ConnectSocket, FIONBIO, (u_long*)&iResult);
#else
	iResult = fcntl(ConnectSocket, F_GETFL, 0);
	if (iResult == -1) {
		closesocket(ConnectSocket);
		throw std::runtime_error(strerror(errno));
	}
	if (fcntl(ConnectSocket, F_SETFL, iResult | O_NONBLOCK) == -1) {
		closesocket(ConnectSocket);
		throw std::runtime_error(strerror(errno));
	}
#endif

	// 连接到服务器
	iResult = connect(ConnectSocket, (struct sockaddr*) & addr, sizeof(struct sockaddr));

	if (iResult < 0) {

#if defined(_WIN32)
		if (WSAGetLastError() == WSAEWOULDBLOCK) {
#else
		if (errno == EINPROGRESS) {
#endif
			do {
				struct timeval timeo;
				timeo.tv_sec = 0;
				timeo.tv_usec = 500000;
				fd_set myset;
				FD_ZERO(&myset);
				FD_SET(ConnectSocket, &myset);
				iResult = select(ConnectSocket + 1, NULL, &myset, NULL, &timeo);
				if (iResult < 0
#ifdef __linux__
					&& errno != EINTR
#endif // __linux__
					) {
					closesocket(ConnectSocket);
					throw std::runtime_error("Connect failed");
				}
				else if (iResult > 0) {
					// Socket selected for write 
					socklen_t lon = sizeof(int);
					int valopt;
					if (getsockopt(ConnectSocket, SOL_SOCKET, SO_ERROR, (char*)(&valopt), &lon) < 0) {
						closesocket(ConnectSocket);
						throw std::runtime_error("Connect failed");
					}
					// Check the value returned... 
					if (valopt) {
						closesocket(ConnectSocket);
						throw std::runtime_error("Connect failed");
					}
					break;
				}
				else {
					closesocket(ConnectSocket);
					throw std::runtime_error("Connect failed");
				}
			} while (true);
		}
		else {
			closesocket(ConnectSocket);
			throw std::runtime_error(strerror(errno));
		}
	}

	// 取消非阻塞
#if defined(_WIN32)
	iResult = 0;
	ioctlsocket(ConnectSocket, FIONBIO, (u_long*)&iResult);
#else
	iResult = fcntl(ConnectSocket, F_GETFL, 0);
	if (iResult == -1) {
		throw std::runtime_error(strerror(errno));
	}
	if (fcntl(ConnectSocket, F_SETFL, iResult & (~O_NONBLOCK)) == -1) {
		throw std::runtime_error(strerror(errno));
	}
#endif

	BasicTcpStream tcpInOut(ConnectSocket, 16);
	std::ostringstream handshake;
	handshake.put(0x00); //packet id for handshake
	writeVarInt(handshake, 578); //protocol version
	char* host = new char[16];
	if (inet_ntop(AF_INET, &addr.sin_addr, host, 16) == NULL)
		LOGE("can not paras host addr");
	iResult = std::strlen(host);
	writeVarInt(handshake, iResult); //host length
	handshake.write(host, iResult); //host string
	delete[] host;
	host = nullptr;
	handshake.write((const char*)&addr.sin_port, 2); //port
	writeVarInt(handshake, 1); //state (1 for status)

	writeVarInt(tcpInOut, handshake.str().size()); //prepend size
	tcpInOut << handshake.str(); //write handshake packet
	tcpInOut.sync();

	tcpInOut.put(0x01); //size is only 1
	tcpInOut.put(0x00); //packet id for status
	tcpInOut.sync();
	readVarInt(tcpInOut); //size of packet
	int id = readVarInt(tcpInOut); //packet id

	if (id == -1) {
		closesocket(ConnectSocket);
		throw std::runtime_error("Premature end of stream.");
	}

	if (id != 0x00) { //we want a status response
		closesocket(ConnectSocket);
		throw std::runtime_error("Invalid packetID");
	}
	int length = readVarInt(tcpInOut); //length of json string

	if (length == -1) {
		closesocket(ConnectSocket);
		throw std::runtime_error("Premature end of stream.");
	}

	if (length == 0 || length > 1048576) {
		closesocket(ConnectSocket);
		throw std::runtime_error("Invalid string length.");
	}

	char* in = new char[length];
	tcpInOut.read(in, length); //read json string
	std::stringstream json;
	json.write(in, length);
	closesocket(ConnectSocket);
	delete[] in;
	in = nullptr;
	Json::Value root;
	json >> root;
	return root;
}

bool isPublicAddr(const unsigned int addr) {
	if ((addr >> 24 & 255) == 0 ||
		(addr >> 24 & 255) == 127 ||
		((addr & 0xf0000000) == 0xe0000000)) {
		return false;
	}

	if ((addr >> 24 & 255) == 10 ||
		(addr >> 24 & 255) == 172 && (addr >> 16 & 240) == 16 ||
		(addr >> 24 & 255) == 192 && (addr >> 16 & 255) == 168) {
		// refer to RFC 1918
		// 10/8 prefix
		// 172.16/12 prefix
		// 192.168/16 prefix
		return false;
	}

	if ((((addr >> 24) & 0xFF) == 169)
		&& (((addr >> 16) & 0xFF) == 254)) {
		// link-local unicast in IPv4 (169.254.0.0/16)
		// defined in "Documenting Special Use IPv4 Address Blocks
		// that have been Registered with IANA" by Bill Manning
		// draft-manning-dsua-06.txt
		return false;
	}

	return true;
}

void scan_thread_fun(const unsigned int start) {
	//Byte addr[4];
	for (unsigned int i = start;
#ifdef USE_LARGE_MEM
		i < (start | 0x0000ffffL);
#else
		i < (start | 0x00ffffffL);
#endif
		i++) {
		//int2byte(i, addr);
		//if (addr[0] == 127 || addr[0] == 0) continue;
		if (!isPublicAddr(i)) continue;

		try {
			struct sockaddr_in sock_addr;
			ZeroMemory(&sock_addr, sizeof(sock_addr));
			sock_addr.sin_family = AF_INET; // IPv4
			sock_addr.sin_port = htons(25565); // short, network byte order
			sock_addr.sin_addr.s_addr = htonl(i);

			//if (!address.isReachable(5000)) continue;
			const Json::Value response = status(sock_addr);
			char* host = new char[16];
			if (inet_ntop(AF_INET, &sock_addr.sin_addr, host, 16) == NULL)
				LOGE("can not paras host addr");
			mtx.lock();
			std::cout << host;
			delete[] host;
			host = nullptr;
			std::cout << ", ";
			const Json::Value version = response["version"];
			if (!version.isNull()) std::cout << "version: " << version["name"].asString() << '(' << version["protocol"].asInt() << "), ";
			const Json::Value motd = response["description"];
			if (!motd.isNull()) {
				std::cout << motd.get("text", "").asString();
				const Json::Value extra = motd["extra"];
				for (int index = 0; index < extra.size(); ++index)
					std::cout << extra[index].get("text", "").asString();
			}
			std::cout << std::endl;
			mtx.unlock();
		}
		catch (const std::exception & e) {
			//e.printStackTrace();
			/*char* host = new char[16];
			unsigned long sin_addr = htonl(i);
			if (inet_ntop(AF_INET, &sin_addr, host, 16) == NULL)
				LOGE("can not paras host addr");
			mtx.lock();
			std::cerr << host << std::endl;
			mtx.unlock();
			delete[] host;*/
		}
	}
}

int
#ifdef _WIN32
__cdecl
#endif
main(int argc, char* argv[])
{
	int iResult;
	//Json::StreamWriterBuilder wbuilder;
	//wbuilder["commentStyle"] = "None"; // json注释的样式
	//wbuilder["indentation"] = ""; // 换行缩进用的符号

	if (sizeof(int) != 4) Exit("sizeof int error");
	if (sizeof(unsigned int) != 4) Exit("sizeof unsigned error");

#ifdef _WIN32
	WSADATA wsaData;

	// 初始化 Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		LOGE("WSAStartup failed: " << iResult);
		return EXIT_FAILURE;
	}
#endif

	std::vector<std::thread *> threads;

	for (short a = 0x1; a < 0xef; a++) {
#ifdef USE_LARGE_MEM
		for (short b = 0x0; b <= 0xff; b++) {
			const unsigned int start = ((a << 24) & 0xff000000L) | ((b << 16) & 0xff0000L);
#else
		const unsigned int start = (a << 24) & 0xff000000L;
#endif
		try {
			std::thread* scan_thread = new std::thread(scan_thread_fun, start);
			std::declare_reachable(scan_thread);
			threads.push_back(scan_thread);
			//scan_thread->detach();
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
		}
		catch (const std::exception & e) {
			mtx.lock();
			LOGE(e.what());
			mtx.unlock();
		}
#ifdef USE_LARGE_MEM
		}
#endif
	}

	while (!threads.empty()) {
		auto t = threads.back();
		t->join();
		std::undeclare_reachable(t);
		delete t;
		threads.pop_back();
	}

	WSACleanup();
	return EXIT_SUCCESS;
}
