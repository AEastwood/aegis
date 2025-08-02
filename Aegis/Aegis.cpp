// Copyright (c) 2025 Adam Eastwood
// Aegis v1.0.0 Security Module

#include <iostream>
#include <string>
#include <Windows.h>
#include "HWID.h"

constexpr auto RESET = "\x1b[0m";
constexpr auto GREEN = "\x1b[32m";
constexpr auto CYAN = "\x1b[36m";
constexpr auto BOLD = "\x1b[1m";

int main()
{
	SetConsoleTitleA("[Aegis] v1.0.0");

	HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
	DWORD dwMode = 0;
	GetConsoleMode(hOut, &dwMode);
	SetConsoleMode(hOut, dwMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);

	std::cout << "[Aegis]: " << BOLD << "Initialising.." << RESET << "\n";
	std::cout << "[Aegis]: Fingerprint: " << CYAN << HWID::GetHWIDHash() << RESET << "\n";

	std::cin.ignore();
}
