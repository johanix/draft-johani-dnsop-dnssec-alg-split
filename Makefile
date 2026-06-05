DRAFT = draft-johani-dnsop-dnssec-large-ksk-sig
VERSION = 00

all: $(DRAFT)-$(VERSION).txt $(DRAFT)-$(VERSION).html

%.xml: %.md
	kramdown-rfc $< > $@

%.txt: %.xml
	xml2rfc --text $<

%.html: %.xml
	xml2rfc --html $<

clean:
	rm -f $(DRAFT)-*.xml $(DRAFT)-*.txt $(DRAFT)-*.html

.PHONY: all clean
