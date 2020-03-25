#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <string.h>
#include <strings.h>
#include <sys/time.h>
#include "lutf.h"
#include "lutf_message.h"

static lutf_rc_t doNonBlockingConnect(int iSockFd, struct sockaddr *psSA,
				      int iSAlen, int iNsec)
{
	int iN, iError = 0;
	int iLen;
	fd_set rset, wset;
	struct timeval tval;

	if ((iN = connect(iSockFd, (struct sockaddr *)psSA, iSAlen)) < 0) {
		if (errno != EINPROGRESS) {
			PERROR("Connect Failed: %s:%d", strerror(errno), errno);
			return EN_LUTF_RC_FAIL;
		}
	}

	if (iN != 0) {
		FD_ZERO(&rset);
		FD_SET(iSockFd, &rset);
		wset = rset;
		tval.tv_sec = iNsec;
		tval.tv_usec = 0;

		if ((iN = select(iSockFd+1, &rset, &wset, NULL,
				 iNsec ? &tval : NULL)) == 0) {
			errno = ETIMEDOUT;
			PERROR("Select timed out");
			return EN_LUTF_RC_FAIL;
		}

		if (iN < 0)
			return EN_LUTF_RC_FAIL;

		if (FD_ISSET(iSockFd, &rset) || FD_ISSET(iSockFd, &wset)) {
			iLen = sizeof(iError);
			if (getsockopt(iSockFd, SOL_SOCKET, SO_ERROR, &iError, (socklen_t *)&iLen) < 0) {
				PERROR("getsockopt failed indicating connect failure, errno= %d", errno);
				return EN_LUTF_RC_FAIL;
			}
		} else {
			PERROR("select error: sockfd not set");
			return EN_LUTF_RC_FAIL;
		}
	}

	/* There was some error when connecting */
	if (iError) {
		errno = iError;
		PERROR("Error on connect. errno = %s", strerror(errno));
		return EN_LUTF_RC_FAIL;
	}

	return EN_LUTF_RC_OK;
}

int establishTCPConnection(unsigned long uiAddress,
			   int iPort,
			   bool b_non_block,
			   bool endian)
{
	int iOption = 1, iFlags;
	int rsocket;
	struct sockaddr_in tm_addr;
	lutf_rc_t eRc = EN_LUTF_RC_OK;

	/* Create TCP socket */
	if ((rsocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP))
	     == -1)
		return EN_LUTF_RC_FAIL;

	/* Turn off Nagle's algorithm for this TCP socket. */
	setsockopt(rsocket, IPPROTO_TCP, TCP_NODELAY, (void *)&iOption,
		   sizeof(iOption));

	iFlags = 1;
	if (setsockopt(rsocket, SOL_SOCKET, SO_REUSEADDR, (void *)&iFlags,
		       sizeof(iFlags)) < 0) {
		/*  Cannot change the socket options.  */
		close(rsocket);
		return EN_LUTF_RC_FAIL;
	}

	iFlags = fcntl(rsocket, F_GETFL, 0);
	if (b_non_block)
		fcntl(rsocket, F_SETFL, iFlags | O_NONBLOCK);
	else
		fcntl(rsocket, F_SETFL, iFlags & (~O_NONBLOCK));

	/* Set address parameters for TCP connection */
	bzero((char *) &tm_addr, sizeof(tm_addr));
	tm_addr.sin_addr.s_addr = (endian) ? htonl(uiAddress) : uiAddress;
	tm_addr.sin_port = (endian) ? htons(iPort) : iPort;
	tm_addr.sin_family = AF_INET;

	if ((eRc = doNonBlockingConnect(rsocket,
					(struct sockaddr *)&tm_addr,
					sizeof(tm_addr),
					SOCKET_CONN_TIMEOUT_SEC))
	    != EN_LUTF_RC_OK) {
		close(rsocket);
		return eRc;
	}

	return rsocket;
}

lutf_rc_t closeTcpConnection(int iTcpSocket)
{
	int rc;

	PDEBUG("closing socket %d", iTcpSocket);
	rc = close(iTcpSocket);
	if (!rc && errno != EINPROGRESS && errno != ECONNRESET) {
		PERROR("failed to close %d:%d\n", iTcpSocket, errno);
		return EN_LUTF_RC_FAIL;
	}

	return EN_LUTF_RC_OK;
}

/*
 * sendTcpMessage
 *   Send a TCP message to the specified TCP socket.
 *
 * Parameters:      iTcpSocket - Socket file descriptor
 *                  pcBody - TCP message to send.
 *                  iBodySize - size of the body
 *
 */
lutf_rc_t sendTcpMessage(int iTcpSocket, char *pcBody, int iBodySize)
{
	size_t tNleft;
	ssize_t tNwritten;
	char *pcCur;

	if (iTcpSocket == INVALID_TCP_SOCKET)
		return(EN_LUTF_RC_FAIL);

	/* Start writing bytes to the socket and keep writing until we have
	 * the requested number of bytes sent.
	 */
	pcCur = (char *)pcBody;
	tNleft = iBodySize;

	while (tNleft > 0) {
		/*  Send as many bytes, up to current maximum, as we can.  */
		tNwritten = write(iTcpSocket, pcCur, tNleft);

		if (tNwritten < 0) {
			if (errno == EINTR) {
				/* We were interrupted, but this is not an
				 * error condition.
				 */
				tNwritten = 0;
			} else {
				/* System error has occurred.  */
				PERROR("Failed to send message (%d, %p, %d, %u)  %s:%d",
				       iTcpSocket, pcBody, iBodySize, tNwritten,
				       strerror(errno), errno);
				return EN_LUTF_RC_SYS_ERR;
			}
		}

		tNleft -= tNwritten;
		pcCur += tNwritten;
	}

	return EN_LUTF_RC_OK;
}

/*
 * populateMsgHdr
 *	populate the LUTF message header with the passed in information.
 *
 * Parameters:      rsocket - Socket file descriptor
 *                  msg_hdr - pointer to the message header.
 *                  msg_type - type of message
 *                  msg_size - message size
 *                  lutf_version_number - version number
 *
 */
lutf_rc_t populateMsgHdr(int rsocket, char *msg_hdr,
			 int msg_type, int msg_size,
			 int lutf_version_number)
{
	lutf_message_hdr_t *hdr = NULL;
	struct sockaddr_in sock;
	int len = sizeof(sock);
	int rc;

	if (rsocket == INVALID_TCP_SOCKET ||
	    msg_hdr == NULL) {
		PERROR("bad parameter: hdr = %p, socket = %d",
		       msg_hdr, rsocket);
		return EN_LUTF_RC_FAIL;
	}

	hdr = (lutf_message_hdr_t *)msg_hdr;

	/* get the local IP address we are connected on */
	rc = getsockname(rsocket,
			(struct sockaddr *)&sock,
			(socklen_t *)&len);
	if (rc) {
		PERROR("getsockname failure %s:%s:%d",
		       strerror(errno), strerror(rc), rc);
		return EN_LUTF_RC_FAIL;
	}

	hdr->type = htonl(msg_type);
	hdr->len = htonl(msg_size);
	hdr->ip.s_addr = sock.sin_addr.s_addr;
	hdr->version = htonl(lutf_version_number);

	return EN_LUTF_RC_OK;
}

lutf_rc_t readTcpMessage(int iFd, char *pcBuffer,
			 int iBufferSize, int iTimeout)
{
	size_t tNleft;
	ssize_t tNread;
	char *pcCur;
	struct timeval sTimeout;
	int iFlags;

	/* Grab a copy of the client's file descriptor
	 * (and make sure it isn't -1).
	 */
	if (iFd == -1)
		return EN_LUTF_RC_CLIENT_CLOSED;

	/* set the timeout */
	if (iTimeout) {
		sTimeout.tv_sec = iTimeout;
		sTimeout.tv_usec = 0;
		setsockopt(iFd, SOL_SOCKET, SO_RCVTIMEO, (void *)&sTimeout,
				sizeof(sTimeout));
		setsockopt(iFd, SOL_SOCKET, SO_SNDTIMEO, (void *)&sTimeout,
				sizeof(sTimeout));

		iFlags = fcntl(iFd, F_GETFL, 0);
		fcntl(iFd, F_SETFL, iFlags & (~O_NONBLOCK));
	} else {
		/* if no timeout specified do a non blocking read */
		iFlags = fcntl(iFd, F_GETFL, 0);
		fcntl(iFd, F_SETFL, iFlags | O_NONBLOCK);
	}

	/* Start reading in bytes from the socket and keep reading until we have
	 * the requested number of bytes or EOF occurs.
	 */
	pcCur = pcBuffer;
	tNleft = iBufferSize;
	while (tNleft > 0) {
		/*  Get as many bytes, up to current maximum as we can.  */
		tNread = read(iFd, pcCur, tNleft);

		if (tNread < 0) {
			if (errno == EINTR) {
				/*  We were interrupted, but this is not an error condition.  */
				tNread = 0;
			} else if ((errno == EAGAIN) && (!iTimeout)) {
				return EN_LUTF_RC_SOCKET_FAIL;
			} else {
				/*  System error has occurred. */
				return EN_LUTF_RC_SOCKET_FAIL;
			}
		} else {
			if (tNread == 0) {
				/* End of file encountered. This is most
				 * likely the client closing their end of the
				 * socket.
				 */
				return EN_LUTF_RC_SOCKET_FAIL;
			}
		}

		tNleft -= tNread;
		pcCur += tNread;
	}

	return EN_LUTF_RC_OK;
}

lutf_rc_t lutf_send_msg(int fd, char *msg, size_t msg_size,
			lutf_msg_type_t type)
{
	lutf_rc_t rc = EN_LUTF_RC_RPC_FAIL;
	lutf_message_hdr_t hdr;

	rc = populateMsgHdr(fd, (char *)&hdr, type,
			    msg_size, LUTF_VERSION_NUMBER);
	if (rc != EN_LUTF_RC_OK) {
		PERROR("Failed to populate message header");
		return rc;
	}

	rc = sendTcpMessage(fd, (char *)&hdr, sizeof(hdr));
	if (rc != EN_LUTF_RC_OK) {
		PERROR("Failed to send msg header");
		return rc;
	}

	if (msg_size) {
		rc = sendTcpMessage(fd, msg, msg_size);
		if (rc != EN_LUTF_RC_OK) {
			PERROR("Failed to send msg body");
			return rc;
		}
	}

	return rc;
}
