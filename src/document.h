#ifndef DOCUMENT_H_
#define DOCUMENT_H_

#include "forger.h"
#include <map>
#include <vector>

class Document {
private:
    std::string uri;
    int version;
    std::map<int, std::string> text_content;

public:
    static Document* findByUri(std::vector<Document>&, const std::string&);
    Document(const rpc_request& didOpenRequest);
    bool operator==(const std::string& uri) const {
        return this->uri == uri;
    }

    void print_text_content();
    void modifyContent(int start_line, int start_char, int end_line, int end_char, std::string replacement);
    const std::string getLine(int);
};

#endif // DOCUMENT_H_
