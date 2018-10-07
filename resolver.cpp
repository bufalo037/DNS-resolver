#include <stdio.h>
#include <stdlib.h>
#include "resolver.hpp"
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h> //?
#include <netinet/in.h>
#include <unistd.h>

char *get_server(char *server, FILE *dns_server)
{
	int n;
	while(1)
	{
		server = fgets(server, Maxbuff, dns_server);
		if(server != NULL && (n = strlen(server)) != 0)
		{
			if(server[0] != '#' || server[0] != ' ' || server[0] != '\n')
			{
				if(server[n-1] == '\n')
				{
					server[n-1] = '\0';
				}
				return server;
			}
		}
		else
		{
			perror("Unable to get dns server");
			exit(EXIT_FAILURE);
		}
	}
	return NULL;
}


int populate_sockaddr_in(sockaddr_in* saddr , const char* addr)
{
	saddr->sin_family = AF_INET;
	saddr->sin_port = htons(53);
	if(inet_aton(addr, &saddr->sin_addr) == 0)
	{
		perror("Eroare la adresa\n");
		return -1;
	}
	return 0;
}


unsigned char htonc(unsigned char cuv)
{
	unsigned char rez = 0;
	unsigned char mask1 = 128;
	unsigned char mask2 = 1;
	while(mask1 != 0)
	{
		if(mask1 & cuv)
		{
			rez += mask2;
		}
		mask1 >>= 1;
		mask2 <<= 1;
	}
	return rez;
}


unsigned short codificare_type(char *type)
{
	if(strcmp(type, "A") == 0)
		return A;
	if(strcmp(type, "NS") == 0)
		return NS;
	if(strcmp(type, "CNAME") == 0)
		return CNAME;
	if(strcmp(type, "MX") == 0)
		return MX;
	if(strcmp(type, "SOA") == 0)
		return SOA;
	if(strcmp(type, "TXT") == 0)
		return TXT;
	if(strcmp(type, "PTR") == 0)
		return PTR;
	perror("Invalid type");
	exit(EXIT_FAILURE);
	return -1;
}

const char *decodificare_type(unsigned short code)
{
	switch(code)
	{
		case A:
			return "A";
		case NS:
			return "NS";
		case CNAME:
			return "CNAME";
		case MX:
			return "MX";
		case SOA:
			return "SOA";
		case TXT:
			return "TXT";
		case PTR:
			return "PTR";
		default:
			return "NAN";
	}
}


dns_header_t *construct_msg_query_header()
{
	srand(time(NULL));
	dns_header_t *header = (dns_header_t *)malloc(sizeof(dns_header_t));
	unsigned short ID = rand() % 65355;
	//unsigned short ID = 42;
	header->id = htons(ID);

	header->rd = 1;
	header->tc = 0; // presupun ca nu o sa dau nicidoata un mesaj trunchiat
	header->aa = 0;
	header->opcode = 0; 
	header->qr = 0;

	header->rcode = 0;
	header->z = 0;
	header->ra = 0;

	// urmatorii bytes sunt constanti pentru implementarea acestui resolver
	header->qdcount = htons(1);
	header->ancount = 0;
	header->nscount = 0;
	header->arcount = 0;

	return header;
}


unsigned int frequency_of_char(char* cuv, char cautat)
{	
	char *ptr;
	unsigned int counter = 0;
	ptr = strchr(cuv, cautat);
	while(ptr)
	{
		counter++;
		ptr = strchr(ptr + 1, cautat);
	}
	return counter;
}


char *make_question(char *name_dom, char* type, unsigned int *len_msg)
{
	char *name = (char *)malloc(sizeof(char) * (strlen(name_dom) + 1));
	memcpy(name, name_dom, strlen(name_dom) + 1);
	dns_question_t *question = (dns_question_t *)malloc(sizeof(dns_question_t));
	question->qtype = htons(codificare_type(type));
	question->qclass = htons(0x0001);
	//question->qclass = htons(1);

	unsigned int nr_domains = frequency_of_char(name, '.') + 1;
	unsigned int contor = 0;
	unsigned int offset = 0;
	unsigned int nr_byes_msg = 0;
	unsigned int *len = (unsigned int *)malloc(sizeof(unsigned int) * nr_domains);
	char *segmentation_ptr;
	char *msg;

	//verifica alocarea
	char **domain_names = (char **)malloc(sizeof(char *) * nr_domains);

	for(unsigned int i = 0; i < nr_domains; i++)
	{
		domain_names[i] = (char *)malloc(sizeof(char) * Maxdomain);
	}

	//name este distrus
	segmentation_ptr = strtok(name, ".");
	while(segmentation_ptr)
	{
		strcpy(domain_names[contor++], segmentation_ptr);
		segmentation_ptr = strtok(NULL, ".");
	}

	for(unsigned int i = 0; i < nr_domains; i++)
	{
		len[i] = strlen(domain_names[i]);
		nr_byes_msg += len[i];
	}

	nr_byes_msg += nr_domains + 1;
	nr_byes_msg += 4; // qtype qclass

	if(strspn(domain_names[0], "1234567890") == 0)
	{
		msg = (char *)malloc(sizeof(char) * nr_byes_msg);
		for(unsigned int i = 0; i < nr_domains; i++)
		{
			msg[offset++] = len[i];
			memcpy(msg + offset, domain_names[i], len[i]);
			offset += len[i];
		}
		msg[offset++] = 0x00;
		memcpy(msg + offset, question, sizeof(dns_question_t));
	}
	else
	{
		// strlen(arpa)14 - 1(0x00) pentru ca este deja adaugat la arpa 
		nr_byes_msg += SizeOfArpa - 1;

		msg = (char *)malloc(sizeof(char) * nr_byes_msg);
		for(int i = nr_domains -1; i >= 0; --i)
		{
			msg[offset++] = len[i];
			memcpy(msg + offset, domain_names[i], len[i]);
			offset += len[i];
		}
		memcpy(msg + offset, arpa, SizeOfArpa);
		offset += SizeOfArpa;
		memcpy(msg + offset, question, sizeof(dns_question_t));

	}

	for(unsigned int i = 0; i < nr_domains; i++)
	{
		free(domain_names[i]);
	}
	free(question);
	free(len);
	free(domain_names);
	free(name);
	*len_msg = nr_byes_msg;
	return msg;
}


char *read_domain(char *msg, unsigned int *offset, unsigned int
 *efective_offset, char* domain)
{
	int i, n;
	unsigned int ef = 0;
	unsigned int len = 0;
	*offset = 0;
	*efective_offset = 0;
	unsigned short ptr;
	char *name = (char *)malloc(sizeof(char) * Maxbuffudp);
	while(*domain != '\0')
	{
		if(*((unsigned char *)domain) <= 63)
		{
			n = *domain;
			domain++;
			(*efective_offset)++;
			// TODO: use memcpy
			for(i = 0; i < n; i++)
			{
				name[(*offset)++] = *domain;
				domain++;
				(*efective_offset)++;
			}
			name[(*offset)++] = '.';
		}
		else
		{
			char *aux;
			ptr = ntohs(*(unsigned short *)domain);
			// scap de cei 2 biti care imi precizeaza ca valoarea este un ptr
			ptr <<= 2;
			ptr >>= 2;
			*efective_offset += 2;
			aux = read_domain(msg, &len, &ef, msg + ptr);
			memcpy(name + (*offset), aux, len + 1);
			*(offset) += len;
			free(aux);
			return name;
		} 
	}
	(*efective_offset)++;
	name[(*offset)] = '\0';
	return name;
}


char *get_rdata(char *msg, const char *type, char *rdata, unsigned short len)
{
	unsigned int temp;
	unsigned int offset_dom = 0, efective_offset_sum = 0;
	unsigned int offset = 0, efective_offset = 0;
	char *message;
	char *domain;
	int n;
	if(strcmp(type, "A") == 0)
	{
		message = (char *)malloc(sizeof(char) *15);
		memcpy(message, inet_ntoa(*((struct in_addr *)rdata)),
		 strlen(inet_ntoa(*((struct in_addr *)rdata))) + 1);
		return message;
	}
	if(strcmp(type, "NS") == 0)
	{
		return read_domain(msg, &offset_dom, &efective_offset, rdata);
	}
	if(strcmp(type, "CNAME") == 0)
	{
		return read_domain(msg, &offset_dom, &efective_offset, rdata);
	}
	if(strcmp(type, "MX") == 0)
	{
		message = (char *)malloc(sizeof(char) * Maxbuffudp);
		offset += sprintf(message, "%hu ", ntohs(*((unsigned short *)rdata)));
		efective_offset_sum += 2;

		domain = read_domain(msg, &offset_dom, &efective_offset,
		 rdata + efective_offset_sum);

		memcpy(message + offset, domain, offset_dom + 1);
		return message;

	}
	if(strcmp(type, "SOA") == 0)
	{
		message = (char *)malloc(sizeof(char) * Maxbuffudp);

		domain = read_domain(msg, &offset_dom, &efective_offset, rdata);
		memcpy(message, domain, offset_dom);
		efective_offset_sum += efective_offset;
		offset += offset_dom;
		message[offset++] = ' ';
		free(domain);

		domain = read_domain(msg, &offset_dom, &efective_offset,
		 rdata + efective_offset_sum);
		memcpy(message + offset, domain, offset_dom);
		efective_offset_sum += efective_offset;
		offset += offset_dom;
		message[offset++] = ' ';
		free(domain);

		temp = ntohl(*((unsigned int *)(rdata + efective_offset_sum)));
		offset += sprintf(message + offset, "%u", temp);
		message[offset++] = ' ';
		efective_offset_sum += 4;

		temp = ntohl(*((unsigned int *)(rdata + efective_offset_sum)));
		offset += sprintf(message + offset, "%u", temp);
		message[offset++] = ' ';
		efective_offset_sum += 4;

		temp = ntohl(*((unsigned int *)(rdata + efective_offset_sum)));
		offset += sprintf(message + offset, "%u", temp);
		message[offset++] = ' ';
		efective_offset_sum += 4;

		temp = ntohl(*((unsigned int *)(rdata + efective_offset_sum)));
		offset += sprintf(message + offset, "%u", temp);
		efective_offset_sum += 4;

		return message;

	}
	if(strcmp(type, "TXT") == 0)
	{	
		message = (char *)malloc(sizeof(char) * Maxbuffudp);
		// conform rfc primul byte indica lungimea stringului si pot fi mai
		// multe stringuri.
		while(len)
		{
			n = (*rdata);
			rdata++;
			memcpy(message + offset, rdata, n);
			rdata += n;
			offset += n;
			len -= n + 1;
		}
		return message;
	}
	if(strcmp(type, "PTR") == 0)
	{
		return read_domain(msg, &offset_dom, &efective_offset, rdata);
	}

	perror("IMPOSIBIL");
	exit(EXIT_FAILURE);
}


void interpret_message(char *msg, char *server, char *query, char * typeq)
{
	if(((dns_header_t *)msg)->qr == 0)
	{
		perror("Not an responce");
		exit(EXIT_FAILURE);
	}

	FILE *dns_responses; 
	dns_responses = fopen("dns.log", "at");

	char clasa[3];
	unsigned short rdlen;
	unsigned int len_domain = 0, ef_dom_offset = 0;
	char question = 0, answer = 0, autority = 0, aditional = 0;
	unsigned int offset = 0;
	char const *type;
	char *domain;
	char *rdata;
	unsigned short qdcount = ntohs(((dns_header_t *)msg)->qdcount);
	unsigned short ancount = ntohs(((dns_header_t *)msg)->ancount);
	unsigned short nscount = ntohs(((dns_header_t *)msg)->nscount);
	unsigned short arcount = ntohs(((dns_header_t *)msg)->arcount);
	memcpy(clasa, "IN", 3);
	offset += sizeof(dns_header_t);
	fprintf(dns_responses, "; %s - %s %s\n\n", server, query, typeq);
	
	while(qdcount--)
	{
		domain = read_domain(msg, &len_domain, &ef_dom_offset, msg + offset);
		offset += ef_dom_offset;
		type = decodificare_type(ntohs((((dns_question_t *)(msg + offset))->qtype)));
		offset += sizeof(dns_question_t);
		if(question == 0)
		{
			question = 1;
			fprintf(dns_responses, ";; QUESTION SECTION:\n");
		}
		fprintf(dns_responses, "%s %s %s\n", domain, clasa, type);
		free(domain);
	}
	if(question == 1)
	{
		fprintf(dns_responses,"\n\n");
	}


	while(ancount--)
	{
		domain = read_domain(msg, &len_domain, &ef_dom_offset, msg + offset);
		offset += ef_dom_offset;
		type = decodificare_type(ntohs((((dns_rr_t *)(msg + offset))->type)));
		rdlen = ntohs(((dns_rr_t *)(msg + offset))->rdlength);
		offset += sizeof(dns_rr_t);
		if(strcmp(type, "NAN") != 0)
		{
			if(answer == 0)
			{
				answer = 1;
				fprintf(dns_responses, ";; ANSWER SECTION:\n");
			}
			rdata = get_rdata(msg, type, msg + offset ,rdlen);
			fprintf(dns_responses, "%s %s %s %s\n", domain, clasa, type, rdata);
			free(rdata);
		}
		free(domain);
		offset += rdlen;
	}
	if(answer == 1)
	{
		fprintf(dns_responses,"\n\n");
	}


	while(nscount--)
	{
		domain = read_domain(msg, &len_domain, &ef_dom_offset, msg + offset);
		offset += ef_dom_offset;
		type = decodificare_type(ntohs((((dns_rr_t *)(msg + offset))->type)));
		rdlen = ntohs(((dns_rr_t *)(msg + offset))->rdlength);
		offset += sizeof(dns_rr_t);
		if(strcmp(type, "NAN") != 0)
		{
			if(autority == 0)
			{
				autority = 1;
				fprintf(dns_responses, ";; AUTORITY SECTION:\n");
			}
			rdata = get_rdata(msg, type, msg + offset ,rdlen);
			fprintf(dns_responses, "%s %s %s %s\n", domain, clasa, type, rdata);
			free(rdata);
		}
		free(domain);
		offset += rdlen;
	}
	if(autority == 1)
	{
		fprintf(dns_responses,"\n\n");
	}


	while(arcount--)
	{
		domain = read_domain(msg, &len_domain, &ef_dom_offset, msg + offset);
		offset += ef_dom_offset;
		type = decodificare_type(ntohs((((dns_rr_t *)(msg + offset))->type)));
		rdlen = ntohs(((dns_rr_t *)(msg + offset))->rdlength);
		offset += sizeof(dns_rr_t);
		if(strcmp(type, "NAN") != 0)
		{
			if(aditional == 0)
			{
				aditional = 1;
				fprintf(dns_responses, ";; ADITIONAL SECTION:\n");
			}
			rdata = get_rdata(msg, type, msg + offset ,rdlen);
			fprintf(dns_responses, "%s %s %s %s\n", domain, clasa, type, rdata);
			free(rdata);
		}
		free(domain);
		offset += rdlen;
	}
	if(aditional == 1)
	{
		fprintf(dns_responses,"\n\n");
	}

	fclose(dns_responses);
}


int main(int argc, char **argv)
{
	if(argc != 3)
	{
		perror("Usage ./<name> <domain_name/IP> <type>\n");
		return -1;
	}

	FILE *dns_messages;
	FILE *dns_file_servers;
	dns_messages = fopen("message.log", "at");

	char *server;
	char *dns_question;
	char *send_msg;
	char *recv_msg;
	unsigned int len_question;
	unsigned int len_msg;
	unsigned int len_from = sizeof(struct sockaddr_in);
	int err_code;
	int err_code2;
	int fd_udp;
	dns_header_t *dns_header;
	struct sockaddr_in *address;	
	struct sockaddr_in *from;

	address = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
	from = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
	recv_msg = (char *)malloc(sizeof(char) * Maxbuffudp);

//-----------------------------------------------------------------------------

	fd_udp = socket(AF_INET, SOCK_DGRAM, 0);

//-----------------------------------------------------------------------------

	server = (char *)malloc(sizeof(char) * Maxbuff);
	dns_file_servers = fopen("dns_servers.conf", "rt");
	do
	{
		get_server(server, dns_file_servers);
		err_code = populate_sockaddr_in(address, server);
	}while(err_code == -1);

//-----------------------------------------------------------------------------

	dns_header = construct_msg_query_header();
	dns_question = make_question(argv[1], argv[2], &len_question);

	len_msg = len_question + sizeof(dns_header_t);
	send_msg = (char *)malloc(sizeof(char) * len_msg);
	memcpy(send_msg, dns_header, sizeof(dns_header_t));
	memcpy(send_msg + sizeof(dns_header_t), dns_question, len_question);

//-----------------------------------------------------------------------------

	for(unsigned int i = 0; i < len_msg; i++)
	{
		fprintf(dns_messages, "%02x ",(unsigned char)send_msg[i]);
	}
	fprintf(dns_messages, "\n");

	do
	{
		err_code2 = sendto(fd_udp, send_msg, len_msg, 0, (sockaddr *)address,
	 		sizeof(struct sockaddr_in));
		if(err_code2 == -1)
			do
			{
				get_server(server, dns_file_servers);
				err_code = populate_sockaddr_in(address, server);
			}while(err_code == -1);
		if(err_code2 != -1)
		{
			err_code2 = recvfrom(fd_udp, recv_msg, Maxbuffudp, 0,
	 			(sockaddr *)from, &len_from);
			if(err_code2 == -1)
				perror("Eroare primire mesaj\n");
		}
	}while(err_code2 == -1);

	interpret_message(recv_msg, server, argv[1], argv[2]);
	// inchidere resurse
	fclose(dns_messages);
	fclose(dns_file_servers);
	if(close(fd_udp) == -1)
	{
		perror("Eroare inchidere socket\n");
		return -1;
	}
	free(dns_header);
	free(dns_question);
	free(send_msg);
	free(address);
	free(from);
	free(recv_msg);

	return 0;
}