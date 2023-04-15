def size_(field, fallback=0):
  """Return the size of an array, or a fallback value if the field is not an array."""
  return {
    "$cond": {
      "if": {
        "$isArray": field
      },
      "then": {
        "$size": field
      },
      "else": fallback
    }
  }

def map_with_guard_(input, output_field, guarded_field, fallback=None):
  """Map over an array, returning a field from each element if a guard passes (the guarded field is not None), otherwise returning a fallback value."""
  return {
    "$map": {
      "input": input,
      "as": "iarr",
      "in": {
        "$cond": {
          "if": { "$ne": [f"$$iarr.{guarded_field}", None] },
          "then": f"$$iarr.{output_field}",
          "else": fallback
        }
      }
    }
  }

def filter_none_(input):
  """Filter out None values from an array."""
  return {
    "$filter": {
      "input": input,
      "as": "iarr",
      "cond": { "$ne": ["$$iarr", None] }
    }
  }