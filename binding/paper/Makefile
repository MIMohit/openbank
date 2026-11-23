# Build the paper. Uses tectonic (user-level, fetches acmart on first run).
# Alternative without tectonic: make docker  (texlive/texlive image, project prefix w2).
OUT ?= build
.PHONY: pdf docker clean
pdf:
	mkdir -p $(OUT)
	tectonic -X compile main.tex --outdir $(OUT) --keep-logs --keep-intermediates
	@grep -E "undefined|Overfull" $(OUT)/main.log | sort -u || true
docker:
	docker run --rm --name w2-latex -v "$(CURDIR)/..":/work -w /work/paper texlive/texlive:latest-medium \
	  latexmk -pdf -outdir=$(OUT) main.tex
clean:
	rm -rf $(OUT)
