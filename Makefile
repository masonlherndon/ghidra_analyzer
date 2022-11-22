
all:

clean-analyzer:
	rm -rf ./analyzer/data/malware/*
	rm -rf ./analyzer/exports/*
	rm -rf ./analyzer/ghidra_done/*
	rm -rf ./analyzer/ghidra_fail/*
	rm -rf ./analyzer/instances/*
	rm -rf ./analyzer/log/*
	rm -rf ./analyzer/projects/*

copy-in-binaries:
	cp ./to_be_analyzed/* ./analyzer/data/malware/

analyze:
	cd ./analyzer/; python3 ./run_ghidra_batches.py

collect-output:
	cp ./analyzer/exports/data/malware/* ./output_JSONs/

prune:
	python3 ./prune_completed_binaries.py

run:
	make clean-analyzer
	make copy-in-binaries
	make analyze
	make collect-output
	make prune

######## UTILITIES ########

clean-all:
	make clean-analyzer
	rm -rf ./output_JSONs/*
	rm -rf ./to_be_analyzed/*

load-test-binaries:
	cp ./test_binaries/* ./to_be_analyzed/

decompress:
	bzip2 -d ./output_JSONs/*

compress:
	bzip2 -z ./output_JSONs/*

run-ghidra-gui:
	./analyzer/ghidra/ghidraRun
