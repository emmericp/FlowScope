#include <signal.h>
#include <atomic>
#include <iostream>

static std::atomic<bool> asserted(false);

static void signal_handler(int) {
	asserted = true;
}

extern "C" {
	// I'm apparently too stupid to use signalfd with SIGUSR1, the masking somehow fails
	void install_signal_handler() {
		signal(SIGUSR1, signal_handler);
	}

	bool check_signal() {
		return asserted.exchange(false);
	}
}
