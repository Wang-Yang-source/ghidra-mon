#include <iostream>
#include <string>

void print_banner() {
    std::cout << "========================================" << std::endl;
    std::cout << "  Welcome to ASCII HELLO WORLD GAME!   " << std::endl;
    std::cout << "========================================" << std::endl;
}

bool check_guess(int guess) {
    // A secret number that we want to reverse engineer
    const int secret = 1337;
    return guess == secret;
}

void print_flag() {
    // A flag/string that can be extracted via strings command
    std::cout << "Correct! Here is your reward: FLAG{ascii_game_reverse_success}" << std::endl;
}

int main() {
    print_banner();
    
    std::cout << "Enter the secret number to win the game: ";
    int guess;
    if (std::cin >> guess) {
        if (check_guess(guess)) {
            print_flag();
        } else {
            std::cout << "Wrong guess! Try again." << std::endl;
        }
    } else {
        std::cout << "Invalid input." << std::endl;
    }
    
    return 0;
}
