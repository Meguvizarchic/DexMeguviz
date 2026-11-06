#include "format/reader.hpp"
#include <fstream>
#include <iostream>
#include <iterator>
#include <vector>

int main(int argc, char** argv) {
    if (argc != 4 || std::string_view(argv[1]) != "inspect" || std::string_view(argv[3]) != "--json") return 1;
    std::ifstream input(argv[2], std::ios::binary);
    if (!input) return 1;
    std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(input)), {});
    try {
        const auto facts = dexmeguviz::read_metadata_with_debug_associations(bytes);
        (void)facts;
        std::cout << "{\"execution_status\":\"Complete\"}\n";
        return 0;
    } catch (const dexmeguviz::ReadError& error) {
        const char* name = error.code == dexmeguviz::ReadCode::corrupt ? "CorruptInput" :
            error.code == dexmeguviz::ReadCode::unsupported ? "Unsupported" : "BudgetExceeded";
        std::cerr << name << ": " << error.what() << " (offset " << error.offset << ")\n";
        return error.code == dexmeguviz::ReadCode::corrupt ? 2 : 3;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
