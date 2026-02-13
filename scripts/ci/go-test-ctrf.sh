#!/bin/bash
# =============================================================================
# Go Test to CTRF Converter
# =============================================================================
#
# Converts go test -json output to CTRF (Common Test Report Format)
# https://ctrf.io/docs/intro
#
# Usage:
#   go test -json ./... | ./scripts/ci/go-test-ctrf.sh > ctrf-results.json
#
# Environment:
#   TOOL_NAME - Name of the tool/suite (default: go-test)
#
# =============================================================================

set -e

TOOL_NAME="${TOOL_NAME:-go-test}"
START_TIME=$(date +%s000)

# Read all input and convert to CTRF format
jq -s '
# Filter to only test results (not package results)
[.[] | select(.Test != null)] as $all_tests |

# Get final status for each test (last action wins)
($all_tests | group_by(.Test) | map({
  name: .[0].Test,
  package: .[0].Package,
  action: .[-1].Action,
  elapsed: ([.[] | .Elapsed // 0] | add)
})) as $tests |

# Count by status
($tests | map(select(.action == "pass")) | length) as $passed |
($tests | map(select(.action == "fail")) | length) as $failed |
($tests | map(select(.action == "skip")) | length) as $skipped |

{
  "results": {
    "tool": {
      "name": "'"$TOOL_NAME"'"
    },
    "summary": {
      "tests": ($passed + $failed + $skipped),
      "passed": $passed,
      "failed": $failed,
      "pending": 0,
      "skipped": $skipped,
      "other": 0,
      "start": '"$START_TIME"',
      "stop": (now * 1000 | floor)
    },
    "tests": [
      $tests[] | {
        "name": .name,
        "status": (
          if .action == "pass" then "passed"
          elif .action == "fail" then "failed"
          elif .action == "skip" then "skipped"
          else "other"
          end
        ),
        "duration": ((.elapsed * 1000) | floor)
      }
    ]
  }
}
'
