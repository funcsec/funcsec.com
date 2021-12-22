HUGO = ./hugo
RSYNC = /usr/bin/rsync
HFLAGS = -D
PUBLIC = ./public
SITE = funcsec.com 
SVR = ig-11 

.PHONY: clean deploy prod build serve

serve:
	$(HUGO) $(HFLAGS) serve

build: clean
	$(HUGO) $(HFLAGS)

prod: clean
	export HUGO_ENV=production && $(HUGO)

deploy: prod
	$(RSYNC) -rvz $(PUBLIC)/ $(SVR):/var/www/$(SITE)/http/ 

clean:
	$(RM) -r $(PUBLIC)
