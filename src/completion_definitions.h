#ifndef COMPLETION_DEFINITIONS_H_
#define COMPLETION_DEFINITIONS_H_

#include "json.hpp"
#include <iostream>
#include <chrono>
#include <optional>
#include <sstream>
#include <string_view>
#include <vector>

using json = nlohmann::json;

enum completionItemKind {
  Text = 1,
  Method = 2,
  Function = 3,
  Constructor = 4,
  Field = 5,
  Variable = 6,
  Class = 7,
  Interface = 8,
  Module = 9,
  Property = 10,
  Unit = 11,
  Value = 12,
  Enum = 13,
  Keyword = 14,
  Snippet = 15,
  Color = 16,
  File = 17,
  Reference = 18,
  Folder = 19,
  EnumMember = 20,
  Constant = 21,
  Struct = 22,
  Event = 23,
  Operator = 24,
  TypeParameter = 25,
};

class completion_item { // json often means not supported
public:
    static void initialize_tree();
    static std::vector<completion_item> get_completion_list(const std::string&, int);

private:
    static completion_item root;

private: // members
    std::string label;
    std::optional<json> labelDetails;
    std::optional<completionItemKind> kind;
    std::optional<std::vector<completionItemKind>> tags; // Mark as deprecated
    std::optional<std::string> detail;
    std::optional<json> documentation; // Can be markdown but not as a string 😭
    std::optional<bool> preselect;
    std::optional<std::string> sortText;
    std::optional<std::string> filterText;
    std::optional<std::string> insertText;
    std::optional<json> insertTextFormat;
    std::optional<json> insertTextMode;
    std::optional<json> textEdit;
    std::optional<std::string> textEditText;
    std::optional<json> additionalTextEdits;
    std::optional<std::vector<std::string>> commitCharacters;
    std::optional<json> command;
    std::optional<json> data;

    std::vector<completion_item> children;

public: // Getters
    const std::string getLabel() const;
    const std::optional<json> getLabelDetails() const;
    const std::optional<json> getKind() const;
    const std::optional<json> getTags() const;
    const std::optional<json> getDetail() const;
    const std::optional<json> getDocumentation() const;
    const std::optional<json> getPreselect() const;
    const std::optional<json> getSortText() const;
    const std::optional<json> getFilterText() const;
    const std::optional<json> getInsertText() const;
    const std::optional<json> getInsertTextFormat() const;
    const std::optional<json> getInsertTextMode() const;
    const std::optional<json> getTextEdit() const;
    const std::optional<json> getTextEditText() const;
    const std::optional<json> getAdditionalTextEdits() const;
    const std::optional<json> getCommitCharacters() const;
    const std::optional<json> getCommand() const;
    const std::optional<json> getData() const;

public: // Public non static functions
    const completion_item* getChildByName(std::string) const;

private:
    completion_item(std::string_view str) : label(str), children{} {}

    completion_item(const completion_item& other, std::string_view new_label)
        : label(new_label), children(other.children) {}

    bool operator==(const completion_item& rhs) const {
        return this->label == rhs.label;
    }

    void add_child(completion_item*, std::string);
    void add_child(std::string);
};

struct completion_list {
    bool isIncomplete = false;
    std::optional<json> itemDefaults; // Not used
    std::vector<completion_item> items;
};
void to_json(json& j, const completion_item& p);
void to_json(json& j, const completion_list& p);

#endif // COMPLETION_DEFINITIONS_H_
