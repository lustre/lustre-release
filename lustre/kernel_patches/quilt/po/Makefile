QUILT_IN :=   add applied delete diff files import new next patches \
              pop previous push refresh remove series setup top unapplied
SCRIPTS_IN := apatch rpatch patchfns spec2series patchfns
# scripts/parse-patch is perl based

# LINGUAS = ...
# localedir = ...

all: $(LINGUAS:%=%.mo)

%.mo : %.po
	msgfmt --statistics -o $@ $<

%.po : quilt.pot
	msgmerge -o $@ $@ $^

quilt.pot: $(QUILT_IN:%=../quilt/%.in) $(SCRIPTS_IN:%=../scripts/%.in) ../bin/quilt.in
	rm -f quilt.pot; touch quilt.pot
	for file in $+ ; do \
	  bash --dump-po-strings $$file \
	    |msguniq \
	    |msgcat --force-po -F - quilt.pot -o quilt.pot; \
	done

clean:
	rm -f *.mo *~

install: all
	for lang in $(LINGUAS) ; do \
		install -d $(BUILD_ROOT)$(localedir)/$$lang/LC_MESSAGES ; \
		install -m 644 $$lang.mo \
		    $(BUILD_ROOT)$(localedir)/$$lang/LC_MESSAGES/quilt.mo ; \
	done

.PHONY: install clean all
