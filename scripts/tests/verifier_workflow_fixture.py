"""Read a production workflow run block without copying its shell logic."""
def workflow_run(source, helper):
    text = (source/'.github/workflows/hosted-ci.yml').read_text()
    matches = []
    for part in text.split('        run: |\n')[1:]:
        lines = []
        for line in part.splitlines():
            if line and not line.startswith('          '):
                break
            lines.append(line[10:])
        block = '\n'.join(lines) + '\n'
        if 'bash ' in block and helper in block:
            matches.append(block)
    assert len(matches) == 1, (helper, len(matches))
    return matches[0]
