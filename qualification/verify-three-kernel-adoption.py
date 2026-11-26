import json,subprocess
with open("docs/migration/three-kernel-adoption.json") as f:m=json.load(f)
for e in m["files"]:
    result=subprocess.check_output(["git","ls-tree","HEAD","--",e["destination_path"]],text=True).strip()
    meta,path=result.split("\t",1)
    mode,kind,sha=meta.split()
    assert mode==e["mode"] and kind=="blob" and sha==e["blob"] and path==e["destination_path"],e
print("THREE_KERNEL_30_SOURCE_BLOBS_EXACT=PASS")
