import sys

def main():
	ip_raw=input("Please enter ipaddress:")
	ip_list=ip_raw.split('.')
	
	for i in range(4):
		ip_list[i]=format(int(ip_list[i]),'02x')
	ip_hex="".join(ip_list)

	with open('rejectip.conf','r') as f:
		lists=f.readlines()	
		if (ip_hex+"\n" in lists) == True:
			print("This ip is already registered")
			sys.exit()	
		else:
			with open('rejectip.conf','a') as fp:
				fp.write(ip_hex)
				fp.write("\n")
				sys.exit()

if __name__ == "__main__":
	main()
