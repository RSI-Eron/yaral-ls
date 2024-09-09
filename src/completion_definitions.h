#ifndef COMPLETION_DEFINITIONS_H_
#define COMPLETION_DEFINITIONS_H_

#include "json.hpp"
#include <iostream>
#include <chrono>
#include <memory>
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


class CompletionItemProperties { // json often means not supported
private: // members
    std::string label;
    std::optional<json> labelDetails; // For type and description
    std::optional<completionItemKind> kind; // Editor will select an icon based on this field
    std::optional<std::vector<json>> tags; // Mark as deprecated
    std::optional<std::string> detail;
    std::optional<json> documentation; // Can be markdown but not as a string 😭
    std::optional<bool> deprecated;
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

    std::string type;
    bool repeated;

public: // Getters
    const std::string& getType() const;
    bool getRepeated() const;

    const std::string& getLabel() const;
    const std::optional<json> getLabelDetails() const;
    const std::optional<json> getKind() const;
    const std::optional<json> getTags() const;
    const std::optional<json> getDetail() const;
    const std::optional<json> getDeprecated() const;
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

public:
    CompletionItemProperties(std::string label, std::string type,  bool repeated = false, bool deprecated = false, completionItemKind kind = completionItemKind::Field)
        : label(std::move(label)), deprecated(deprecated), type(type), repeated(repeated) {
        if (repeated)
            detail = "repeated";

        if (deprecated) {
            std::vector<json> v;
            json j{{"deprecated", 1}};
            v.push_back(j);
            tags = v;
        }


        #ifdef SHOW_TYPES
        // Show type;
        if (type != "") {
            std::replace(type.begin(), type.end(), '_', '.');
            labelDetails = json{{"description", type}};
        }
        #endif

        this->kind = kind;
    }

    CompletionItemProperties(std::string label, std::string type, completionItemKind kind)
        : CompletionItemProperties(label, type, false, false, kind) {}

    friend bool operator==(const CompletionItemProperties& lhs, const std::string& rhs) {
        return lhs.label == rhs;
    };

    friend bool operator==(const CompletionItemProperties& lhs, const CompletionItemProperties& rhs);
};


namespace std {
    template <>
    struct hash<CompletionItemProperties> {
        std::size_t operator()(const CompletionItemProperties& obj) const {
            // Simple example using only the label for hashing.
            // Adjust this to include other members if necessary.
            return std::hash<std::string>()(obj.getLabel());
        }
    };
}

class CompletionItem {
public:
    static void initialize_tree();
    static const std::vector<CompletionItemProperties> getCompletionList(const std::string&, int);
    static const std::string getHover(const std::string&, int);
    static const std::shared_ptr<CompletionItem> getLeafFromExpression(std::string expression, std::string* leaf);

private:
    static std::shared_ptr<CompletionItem> root;
    std::unordered_map<CompletionItemProperties, std::shared_ptr<CompletionItem>> children;

public:
    const std::shared_ptr<CompletionItem> getChildByName(std::string) const;
    CompletionItem() = default;

private:
    void addChild(const std::string&, std::string type = "string");
    void addChild(const CompletionItemProperties&);
    void addChild(std::shared_ptr<CompletionItem>, const std::string&, std::string type);
    void addChild(std::shared_ptr<CompletionItem>, const CompletionItemProperties&);
};

struct completion_list {
    bool isIncomplete = false;
    std::optional<json> itemDefaults; // Not used
    std::vector<CompletionItemProperties> items;
};
void to_json(json& j, const CompletionItemProperties& p);
void to_json(json& j, const completion_list& p);

#endif // COMPLETION_DEFINITIONS_H_
