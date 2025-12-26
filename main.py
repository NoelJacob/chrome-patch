# %%
import shutil

import lief

# %%
shutil.copy2("/opt/google/chrome/chrome", "./chrome")
shutil.copy2("/opt/google/chrome/chrome", "./chrome.bak")

# %%
ft = {
    "ExtensionManifestV2Unsupported": 0,
    "ExtensionManifestV2Disabled": 0,
    "ExtensionsManifestV3Only": 0,
    "AllowLegacyMV2Extensions": 1,
}

# %%
b = lief.parse("./chrome")
assert b
rodata = b.get_section(".rodata")

rodata_bytes = bytes(rodata.content)
rodata_va = rodata.virtual_address
ft_vas = {}

for name in ft:
    needle = name.encode("utf-8") + b"\x00"
    offset = rodata_bytes.find(needle)

    if offset != -1:
        va = rodata_va + offset
        ft_vas[va] = name
    else:
        print(f"[-] Warning: '{name}' not found in binary")

# %%
ft_reloc = {}

for reloc in b.relocations:
    for va in ft_vas.values():
        addend = reloc.addend
        if addend in ft_vas:
            ft_name = ft_vas[addend]
            reloc_add = reloc.address + 8
            file_offset = b.virtual_address_to_offset(reloc_add)
            ft_reloc[file_offset] = ft_name


# %%
with open("./chrome", "rb+") as f:
    for offset, name in ft_reloc.items():
        f.seek(offset)
        curr = int.from_bytes(f.read(1), byteorder="little")
        new = ft[name]
        if curr == new:
            print(f"{name} already same number")
        else:
            f.seek(offset)
            f.write(bytes([new]))
