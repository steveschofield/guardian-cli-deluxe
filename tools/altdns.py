"""
altdns wrapper for permutation-based DNS enumeration
"""

from typing import Dict, Any, List
from tools.base_tool import BaseTool


class AltdnsTool(BaseTool):
    """altdns wrapper"""

    def get_command(self, target: str, **kwargs) -> List[str]:
        # altdns normally takes a list; here we accept single domain via --input
        input_file = kwargs.get("input_file")
        wordlist = kwargs.get("wordlist")
        output_file = kwargs.get("output_file")

        command = ["altdns"]
        if input_file:
            command.extend(["-i", input_file])
        else:
            # fall back to echoing target
            command.extend(["-i", "-"])
        if wordlist:
            command.extend(["-w", wordlist])
        if output_file:
            command.extend(["-o", output_file])

        return command

    def parse_output(self, output: str) -> Dict[str, Any]:
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        return {"permutations": lines}
