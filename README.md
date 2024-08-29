## Compile
```sh
mkdir build && cd build
cmake ../src
cmake --build .
```

## Use
The server only supports communications through standard input / output.

#### Emacs
It can be used with Emacs lsp-mode.
Adapt this and add it to your configuration by replacing yaral-mode with whatever mode you use for YARA-L files :
```elisp
(defun yaral-activate-lsp ()
  "Activate LSP when entering yaral mode"
  (unless (bound-and-true-p lsp-mode)
    (require 'lsp-mode)
    (lsp!)))

(after! yaral/yaral
    (add-hook! 'yaral-mode-hook #'yaral-activate-lsp))

(after! lsp-mode
  (add-to-list 'lsp-language-id-configuration '(yaral-mode . "yaral"))
  (lsp-register-client
   (make-lsp--client :new-connection (lsp-stdio-connection "yaral-ls")
                     :activation-fn (lsp-activate-on "yaral")
                     :server-id 'yaral-ls)))
```
