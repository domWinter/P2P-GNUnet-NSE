initial=InitialReport
interims=InterimsReport
final=FinalReport

.PHONY: pdf clean

pdf:
	pdflatex -output-directory ./PDF/ ${initial}.tex
	pdflatex -output-directory ./PDF/ ${interims}.tex
	pdflatex -output-directory ./PDF/ ${interims}.tex
	pdflatex -output-directory ./PDF/ ${final}.tex
	pdflatex -output-directory ./PDF/ ${final}.tex
	rm -rf ./PDF/*.log
	rm -rf ./PDF/*.aux
	rm -rf ./PDF/*.out

clean:
	rm -rf ./PDF/*
	rm -rf *.log
	rm -rf *.aux
	rm -rf *.gz
