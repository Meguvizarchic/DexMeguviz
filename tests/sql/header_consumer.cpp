// This consumer links only the adapter target and sets no include directory.
#include "method_tables.hpp"

int main() {
    std::unique_ptr<dexmeguviz::desktop_sql::SqlSession> session;
    return dexmeguviz::desktop_sql::SqlSession::open(nullptr, session) == 0 ? 1 : 0;
}
