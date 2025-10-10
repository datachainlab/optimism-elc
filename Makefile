PHONY: sync-lock
sync-lock:
	cargo update -p kona-client
	cd tools/deps && python sync_lock.py
	# Check build
	cargo build
