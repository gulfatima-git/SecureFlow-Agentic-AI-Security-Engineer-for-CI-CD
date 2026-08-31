def execute(query):
    import subprocess
    return subprocess.call(query, shell=True)
