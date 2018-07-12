

clean:
	sudo rm -rf pcaps
	sudo rm -rf csv
	sudo rm -rf *.com
	sudo rm -rf *.edu
	mkdir pcaps
	mkdir csv

remove:
	sudo rm -rf *.com
	sudo rm -rf *.edu
	find . -type f \( -name \*.pdf -o -name \*png \) -delete
	rm *.pcap
	rm *.csv
