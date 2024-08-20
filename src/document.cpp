#include "document.h"
#include "forger.h"
#include "logger.h"
#include <algorithm>
#include <iostream>
#include <sstream>
#include <string>


Document* Document::findByUri(std::vector<Document>& documents, const std::string& uri) {
  for (auto &doc : documents) {
    if (doc.uri == uri) {
      return &doc;
    }
  }
  return nullptr;
}


void Document::modifyContent(int start_line, int start_char, int end_line, int end_char, std::string replacement) {
    int nb_newlines = std::count(replacement.begin(), replacement.end(), '\n');
    int line_difference = nb_newlines - (end_line - start_line); // Positive is an expansion; Negative is a shrink

    if (line_difference == 0) { // One line change
        text_content[start_line] = text_content[start_line].substr(0, start_char) + replacement + text_content[end_line].substr(end_char);
        //print_text_content();
        return;
    }

    std::map<int, std::string> updated_document;


    // Copy unchanged elements from the beginning
    auto it = text_content.begin();
    auto end = std::next(it, start_line);
    for (; it != end; ++it) {
        updated_document[it->first] = it->second;
    }
    if (start_char != 0)
        updated_document[start_line] = text_content[start_line].substr(0, start_char);

    // Shift end of document
    int n = text_content.size() - end_line - 1;
    for (auto rit = text_content.rbegin(); rit != text_content.rend() && n > 0; ++rit, --n) {
        updated_document[rit->first + line_difference] = rit->second;
    }
    updated_document[end_line + line_difference] = updated_document[end_line + line_difference] + text_content[end_line].substr(end_char);


    // Insert the replacement string
    std::string line;
    std::istringstream ss(replacement);
    int offset = start_line;
    while (std::getline(ss, line)) {
        if (offset == start_line) {
            updated_document[offset] = updated_document[offset] + line;
        } else if (offset == end_line + line_difference) {
            updated_document[offset] = line + updated_document[offset];
        } else {
            updated_document[offset] = line;
        }
        offset += 1;
    }

    // Update the stored document
    text_content = std::move(updated_document);

    //print_text_content();
}

void Document::print_text_content() {
    for (const auto &[lineNumber, line] : text_content) {
        std::cerr << lineNumber+1 << ": " << line << std::endl;
    }
}

Document::Document(const rpc_request& didOpenRequest) {
    json doc = didOpenRequest.params.value()["textDocument"];
    uri = doc["uri"];
    version = doc["version"];

    std::istringstream stream((std::string)doc["text"]);
    std::string line;
    int lineNumber = 0;

    while (std::getline(stream, line, '\n')) {
        text_content[lineNumber++] = line;
    }
    //print_text_content();
}


const std::string Document::getLine(int lineNumber) {
    return text_content[lineNumber];
}
