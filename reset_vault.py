import os
import json

files_to_delete = ['database.json', 'audit_log.txt']

for file in files_to_delete:
    if os.path.exists(file):
        os.remove(file)
        print(f"🗑️ Deleted {file}")
    else:
        print(f"✅ {file} already clean.")

# Create a fresh, empty database
with open('database.json', 'w') as f:
    json.dump({}, f)

print("\n🚀 System Reset! You can now register fresh using the new logic.")