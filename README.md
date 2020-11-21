# injectPE

injectPE is a tool designed to inject shellcode into 32-bit and 64-bit Windows executables.

## Usage
```
.\in .\out .\shellcode option
```
## Options
### Extend .text Section
```
.\in .\out .\shellcode -e
```
Extending code section attempts to expand code section and insert shellcode inside of that section. Section extention cannot exceed virtual address of subsequent section and will increase file size.

```
.\in .\out .\shellcode -n
```
### New Executable Section
Creating a new section will append a new executable section to the end of the PE header and place the shellcode at the end of the file. This will increase file size.

```
.\in .\out .\shellcode -c
```
#### Code Cave
Find a code cave and insert the shellcode inside. Shellcode size cannot exceed file alignment of optional header and will modify section characteristics.
