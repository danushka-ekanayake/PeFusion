# PeFusion
Custom PE Loader for Windows

This custom PE loader is designed to load simple PE files, such as "Hello World" console applications, into memory. It handles several essential tasks to ensure the PE file is correctly loaded and executable, including:

    IAT (Import Address Table) Fixing: Resolves and rewrites IAT entries to ensure proper function calls at runtime.
    Image Relocation Handling: Adjusts memory addresses in the PE file based on the base address it is loaded into.
    Exception Handler Registration: Registers exception handlers to enable proper error handling during execution.

Currently, the loader does not handle the TLS (Thread Local Storage) Directory, and it is only compatible with basic PE files.
