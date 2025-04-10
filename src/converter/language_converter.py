import re
import os
import json
import shutil
import logging
import pathlib # Import pathlib
import argparse # Import argparse
import sys # Import sys
from dataclasses import dataclass, field
from typing import Optional, Dict, Any

# --- Configuration Dataclasses ---
# (FileSection and LanguageConfig remain the same)
@dataclass
class FileSection:
    """Represents a data section within the scenario file."""
    offset: int
    length: int
    count: int = 1
    name_length: Optional[int] = None

@dataclass
class LanguageConfig:
    """Holds all configuration parameters for a specific language version."""
    title: FileSection
    description: FileSection
    faction_description: FileSection
    officer: FileSection
    item: FileSection
    nation: FileSection
    encoding: str
    file_size: int

# --- Global Configuration ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# (LANGUAGE_CONFIGS dictionary remains the same)
LANGUAGE_CONFIGS: Dict[str, LanguageConfig] = {
    "jap": LanguageConfig(
        title=FileSection(offset=0x5e, length=0x10),
        description=FileSection(offset=0x6f, length=0x132),
        faction_description=FileSection(offset=0x274, length=0x138, count=42),
        officer=FileSection(offset=0x3bcd, length=0x98, count=850, name_length=0x35),
        item=FileSection(offset=0x2347d, length=0x39, count=100, name_length=37),
        nation=FileSection(offset=0x271fb, length=0x57, count=0x54, name_length=0x50), # count/length may be less relevant if copying tail
        encoding="shift_jisx0213",
        file_size=0x28E87
    ),
    "cht": LanguageConfig(
        title=FileSection(offset=0x5e, length=0x10),
        description=FileSection(offset=0x6f, length=0x16b), # Offset differs from JA faction start, check original logic
        faction_description=FileSection(offset=0x2ad, length=0x171, count=42),
        officer=FileSection(offset=0x4560, length=0x98, count=850, name_length=0x35),
        item=FileSection(offset=0x23e10, length=0x39, count=100, name_length=37),
        nation=FileSection(offset=0x27b8e, length=0x57, count=0x54, name_length=0x50), # Represents start offset for TC tail copy
        encoding="big5",
        file_size=0x2981a
    ),
    "eng": LanguageConfig(
        title=FileSection(offset=0x5e, length=0x10),
        description=FileSection(offset=0x6f, length=0x16b),
        faction_description=FileSection(offset=0x2ad, length=0x171, count=42),
        officer=FileSection(offset=0x4560, length=0x98, count=850, name_length=0x35),
        item=FileSection(offset=0x23e10, length=0x39, count=100, name_length=37),
        nation=FileSection(offset=0x27b8e, length=0x57, count=0x54, name_length=0x50),
        encoding="latin-1", # Placeholder
        file_size=0x2981a # Placeholder
    )
}

# --- Utility Function ---
# (read_json_data remains the same)
def read_json_data(json_path: pathlib.Path) -> Optional[Dict[str, Any]]:
    """Loads scenario text data from a JSON file (using pathlib.Path)."""
    try:
        resolved_path = json_path.resolve()
        if not resolved_path.is_file():
            logging.error(f"JSON file not found: {resolved_path}")
            return None
        with open(resolved_path, "r", encoding="utf-8") as json_file:
            data = json.load(json_file)
            return {key.lower(): value for key, value in data.items()}
    except FileNotFoundError:
        logging.error(f"JSON file not found: {json_path}")
        return None
    except json.JSONDecodeError as e:
        logging.error(f"Error decoding JSON file {json_path}: {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred while reading JSON {json_path}: {e}")
        return None

# --- Converter Class ---
# (ScenarioLanguageConverter class remains the same as the previous version)
class ScenarioLanguageConverter:
    """
    Handles the conversion of San11 scenario files between languages,
    primarily focusing on text and specific data structure replacements.
    """
    def __init__(self, source_lang: str, target_lang: str, reference_template_path_str: str, json_data_path_str: str):
        if source_lang not in LANGUAGE_CONFIGS or target_lang not in LANGUAGE_CONFIGS:
            raise ValueError("Invalid source or target language specified.")

        self.source_config: LanguageConfig = LANGUAGE_CONFIGS[source_lang]
        self.target_config: LanguageConfig = LANGUAGE_CONFIGS[target_lang]

        json_data_path = pathlib.Path(json_data_path_str).resolve()
        reference_template_path = pathlib.Path(reference_template_path_str).resolve()
        self.reference_template_path: pathlib.Path = reference_template_path

        if not reference_template_path.is_file():
             raise FileNotFoundError(f"Reference template file not found: {reference_template_path}")

        logging.info(f"Loading scenario text data from: {json_data_path}")
        self.scenario_text_data: Optional[Dict[str, Any]] = read_json_data(json_data_path)
        if not self.scenario_text_data:
             raise RuntimeError(f"Failed to load necessary scenario text data from {json_data_path}")

        logging.info(f"Converter initialized for {source_lang.upper()} -> {target_lang.upper()}")

    def _validate_file_size(self, file_path: os.PathLike, expected_size: int, file_desc: str = "File") -> bool:
        """Validates if the actual file size matches the expected size."""
        try:
            actual_size = os.path.getsize(file_path) # os.path.getsize works with Path objects
            if actual_size != expected_size:
                # Use file_path.name for cleaner logging with Path objects
                logging.warning(
                    f"{file_desc} size mismatch for {pathlib.Path(file_path).name}: "
                    f"Actual=0x{actual_size:X}, Expected=0x{expected_size:X}"
                )
                return False
            return True
        except FileNotFoundError:
            logging.error(f"{file_desc} not found during size validation: {file_path}")
            return False
        except Exception as e:
            logging.error(f"Error validating {file_desc} size for {file_path}: {e}")
            return False

    def _prepare_text_block(self, source_block: bytes, text_content: str, target_length: int, preserve_first_byte: bool = True) -> bytes:
        """Encodes text, handles first byte, pads/truncates to target length."""
        if not source_block and preserve_first_byte:
            logging.warning("Source block is empty, cannot preserve first byte.")
            preserve_first_byte = False # Cannot preserve if block is empty

        try:
            encoded_text = text_content.encode(self.target_config.encoding)
        except UnicodeEncodeError as e:
            logging.error(f"Encoding error for text: '{text_content[:30]}...' using {self.target_config.encoding}. Error: {e}")
            encoded_text = b"[ENCODE_ERR]".ljust(target_length - (1 if preserve_first_byte else 0), b'?')[:target_length - (1 if preserve_first_byte else 0)]
        except Exception as e:
             logging.error(f"Unexpected error encoding text '{text_content[:30]}...': {e}")
             encoded_text = b"[ENCODE_ERR]".ljust(target_length - (1 if preserve_first_byte else 0), b'?')[:target_length - (1 if preserve_first_byte else 0)]


        byte_prefix = bytes([source_block[0]]) if preserve_first_byte and source_block else b''
        content_target_len = target_length - len(byte_prefix)

        if len(encoded_text) > content_target_len:
             logging.debug(f"Text content too long, truncating: '{text_content[:30]}...'")
             modified_block = byte_prefix + encoded_text[:content_target_len]
        else:
             modified_block = byte_prefix + encoded_text.ljust(content_target_len, b'\x00')

        # Final length assertion (should normally pass)
        if len(modified_block) != target_length:
             logging.error(f"INTERNAL ERROR: Prepared text block length mismatch. Got {len(modified_block)}, expected {target_length}.")
             modified_block = modified_block.ljust(target_length, b'\x00')[:target_length] # Force length

        return modified_block

    def _prepare_hybrid_block(self, source_data_block: bytes, target_ref_block: bytes, name_part_length: int) -> bytes:
        """Combines name from target reference and data from source."""
        if name_part_length <= 0:
             logging.warning("Name part length is zero or negative, returning source block.")
             return source_data_block

        target_len = len(source_data_block) if source_data_block else (len(target_ref_block) if target_ref_block else 0)
        if target_len == 0:
            logging.warning("Both source and target blocks are empty in hybrid processing.")
            return b''

        if not source_data_block or not target_ref_block:
            logging.warning("Source or Target reference block is empty for hybrid processing.")
            # Return the non-empty block padded/truncated, or empty if both are empty
            block_to_use = source_data_block or target_ref_block or b''
            return block_to_use.ljust(target_len, b'\x00')[:target_len]

        if len(target_ref_block) < name_part_length:
             logging.warning(f"Target reference block shorter than name length ({len(target_ref_block)} < {name_part_length}). Using available part + padding.")
             target_name_part = target_ref_block.ljust(name_part_length, b'\x00')
        else:
             target_name_part = target_ref_block[:name_part_length]

        if len(source_data_block) <= name_part_length:
             logging.warning(f"Source data block not longer than name length ({len(source_data_block)} <= {name_part_length}). No data part to preserve from source.")
             combined = target_name_part.ljust(target_len, b'\x00')[:target_len] # Pad name part to target length
        else:
            source_data_part = source_data_block[name_part_length:]
            combined = target_name_part + source_data_part

        # Ensure final block matches original source length (important for file structure)
        if len(combined) != target_len:
             logging.warning(f"Hybrid block length mismatch ({len(combined)} != {target_len}). Adjusting.")
             combined = combined.ljust(target_len, b'\x00')[:target_len]

        return combined

    def _convert_single_file(self, input_src_path: pathlib.Path, output_target_path: pathlib.Path, target_ref_path: pathlib.Path, scenario_texts: Dict[str, Any]) -> bool:
        """Converts a single scenario file from source to target language."""
        logging.info(f"Processing: {input_src_path.name} -> {output_target_path.name}")

        if not self._validate_file_size(input_src_path, self.source_config.file_size, "Source"):
            logging.error(f"Skipping {input_src_path.name} due to incorrect source file size.")
            return False
        if not target_ref_path.is_file():
            logging.error(f"Target Reference file not found: {target_ref_path}. Skipping {input_src_path.name}.")
            return False
        if not self._validate_file_size(target_ref_path, self.target_config.file_size, "Target Reference"):
             logging.warning(f"Target Reference file {target_ref_path.name} has unexpected size. Proceeding cautiously.")

        try:
            with open(input_src_path, "rb") as infile_src, \
                 open(output_target_path, "wb") as outfile_target, \
                 open(target_ref_path, "rb") as infile_target_ref:

                current_src_pos = 0

                def copy_chunk(target_src_offset: int):
                    nonlocal current_src_pos
                    if target_src_offset > current_src_pos:
                        read_len = target_src_offset - current_src_pos
                        infile_src.seek(current_src_pos)
                        chunk = infile_src.read(read_len)
                        outfile_target.write(chunk)
                        current_src_pos += len(chunk)
                    elif target_src_offset < current_src_pos:
                         logging.error(f"Attempted to copy chunk to an earlier offset (current: 0x{current_src_pos:X}, target: 0x{target_src_offset:X}). Skipping.")

                sections_to_process = [
                    ('title', self.source_config.title, self.target_config.title, True),
                    ('description', self.source_config.description, self.target_config.description, True),
                    ('faction_description', self.source_config.faction_description, self.target_config.faction_description, True),
                    ('officer', self.source_config.officer, self.target_config.officer, False),
                    ('item', self.source_config.item, self.target_config.item, False),
                    ('nation', self.source_config.nation, self.target_config.nation, False),
                ]
                sections_to_process.sort(key=lambda x: x[1].offset)

                for name, src_sec, tgt_sec, is_simple_text in sections_to_process:
                    copy_chunk(src_sec.offset)
                    logging.debug(f"Processing section: {name}")

                    if name == 'nation':
                         infile_target_ref.seek(self.target_config.nation.offset)
                         remaining_target_data = infile_target_ref.read()
                         outfile_target.write(remaining_target_data)
                         logging.debug(f"Wrote remaining data from target reference (0x{len(remaining_target_data):X} bytes from offset 0x{self.target_config.nation.offset:X})")
                         current_src_pos = self.source_config.file_size
                         break

                    if not is_simple_text:
                         infile_target_ref.seek(tgt_sec.offset)

                    for i in range(src_sec.count):
                         infile_src.seek(current_src_pos)
                         src_block = infile_src.read(src_sec.length)
                         current_src_pos += len(src_block)
                         if not src_block and src_sec.count > 1:
                              logging.warning(f"Unexpected end of source file while reading block {i+1}/{src_sec.count} for section '{name}'.")
                              outfile_target.write(b'\x00' * tgt_sec.length)
                              continue

                         if is_simple_text:
                              json_key_map = {'faction_description': 'factions'}
                              text_key = json_key_map.get(name, name)
                              json_data_source = scenario_texts.get(text_key)

                              if src_sec.count == 1:
                                  if isinstance(json_data_source, str):
                                      content = json_data_source
                                  else:
                                      content = f"[MISSING/INVALID {text_key.upper()}]"
                                      if json_data_source is not None:
                                          logging.warning(f"Expected string in JSON for key '{text_key}', found {type(json_data_source)}. Using placeholder.")
                              else: # count > 1
                                  if isinstance(json_data_source, list):
                                       content = json_data_source[i] if i < len(json_data_source) else f"[MISSING {text_key.upper()} {i+1}]"
                                  else:
                                       content = f"[BAD_JSON_DATA {i+1}]"
                                       if json_data_source is not None:
                                           logging.warning(f"Expected list in JSON for key '{text_key}', found {type(json_data_source)}. Using placeholder.")

                              output_block = self._prepare_text_block(src_block, content, tgt_sec.length, preserve_first_byte=True)
                         else: # Hybrid
                              target_ref_block = infile_target_ref.read(tgt_sec.length)
                              if not target_ref_block and src_sec.count > 1:
                                   logging.error(f"Unexpected end of target reference file while reading block {i+1}/{src_sec.count} for section '{name}'.")
                                   output_block = src_block.ljust(tgt_sec.length, b'\x00')[:tgt_sec.length]
                              elif tgt_sec.name_length is None:
                                   logging.error(f"Configuration error: 'name_length' not set for hybrid section '{name}'. Returning source block.")
                                   output_block = src_block.ljust(tgt_sec.length, b'\x00')[:tgt_sec.length]
                              else:
                                   output_block = self._prepare_hybrid_block(src_block, target_ref_block, tgt_sec.name_length)
                         outfile_target.write(output_block)
                copy_chunk(self.source_config.file_size)

        except FileNotFoundError as e:
            logging.error(f"File not found during processing: {e}")
            return False
        except IOError as e:
            logging.error(f"I/O error during processing {input_src_path.name}: {e}")
            return False
        except Exception as e:
            logging.error(f"An unexpected error occurred processing {input_src_path.name}: {e}", exc_info=True)
            if output_target_path.exists():
                 try:
                     output_target_path.unlink()
                     logging.info(f"Removed incomplete output file: {output_target_path}")
                 except OSError as remove_err:
                     logging.error(f"Failed to remove incomplete output file {output_target_path}: {remove_err}")
            return False

        if not self._validate_file_size(output_target_path, self.target_config.file_size, "Output"):
            logging.error(f"Processing FAILED for {input_src_path.name}: Output file size is incorrect.")
            return False
        else:
            logging.info(f"Successfully processed {input_src_path.name}")
            return True

    def convert_all(self, input_dir: pathlib.Path, output_dir: pathlib.Path) -> bool:
        """
        Processes all source scenario files found in the input directory
        and saves the converted target files to the output directory.
        Returns True if all files were processed successfully, False otherwise.
        """
        if not self.scenario_text_data:
            logging.error("No scenario text data loaded. Aborting batch processing.")
            return False
        if not input_dir.is_dir():
            logging.error(f"Input directory not found or not a directory: {input_dir}")
            return False

        output_dir.mkdir(parents=True, exist_ok=True)
        logging.info(f"Output directory set to: {output_dir}")

        file_pattern = re.compile(r"^scen\d{3}\.s11$", re.IGNORECASE)
        success_count = 0
        fail_count = 0
        processed_files = 0

        for item in input_dir.iterdir():
            if item.is_file() and file_pattern.match(item.name):
                processed_files += 1
                input_src_path = item
                output_target_path = output_dir / item.name
                target_ref_path = self.reference_template_path

                scenario_key = item.name.lower()
                scenario_texts_for_file = self.scenario_text_data.get(scenario_key)

                if not scenario_texts_for_file:
                    logging.warning(f"No text data found in JSON for '{scenario_key}'. Skipping file {item.name}.")
                    fail_count += 1
                    continue
                if not target_ref_path.is_file():
                    logging.warning(f"Target reference file '{target_ref_path.name}' not found in {self.reference_template_path.parent}. Skipping {item.name}.")
                    fail_count +=1
                    continue

                if self._convert_single_file(
                    input_src_path,
                    output_target_path,
                    target_ref_path,
                    scenario_texts_for_file
                ):
                    success_count += 1
                else:
                    fail_count += 1
            elif item.is_file():
                 logging.debug(f"Skipping non-matching file: {item.name}")

        logging.info("-" * 30)
        logging.info(f"Batch processing complete.")
        logging.info(f"Processed matching files: {processed_files}")
        logging.info(f"Successfully converted:   {success_count} files")
        logging.info(f"Failed/Skipped:         {fail_count} files")
        logging.info("-" * 30)

        # Return True only if all *processed* files succeeded AND at least one file was processed
        # If no matching files were found, consider it unsuccessful for automation.
        return fail_count == 0 and processed_files > 0


# --- Main Execution ---

def main() -> int:
    """Parses command line arguments and runs the scenario conversion."""
    parser = argparse.ArgumentParser(
        description='Convert Sangokushi XI scenario files between languages',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter # Show defaults in help message
        )
    # Use simple relative paths as defaults - ADJUST AS NEEDED
    # These are relative to the location where the script is run.
    parser.add_argument('-i', '--input', default='output/PC/scenario/', # Changed default
                        help='Input directory with source language .s11 files')
    parser.add_argument('-o', '--output', default='output/PC/cht/scenario/', # Changed default
                        help='Output directory for target language .s11 files')
    parser.add_argument('-s', '--source-lang',
                        choices=LANGUAGE_CONFIGS.keys(), default='jap',
                        help='Source language code')
    parser.add_argument('-t', '--target-lang',
                        choices=LANGUAGE_CONFIGS.keys(), default='cht',
                        help='Target language code')
    parser.add_argument('-tr', '--translations',
                        default='./resources/cht/descriptions.json', # Changed default
                        help='Path to the JSON file with target language text replacements')
    parser.add_argument('-n', '--names-template',
                        default='./resources/cht/SCEN007.S11', # Changed default (using SCEN000)
                        help='Path to a single target language Scenario file (.s11) to use as a template for names/hybrid sections')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Enable verbose debug logging')

    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.getLogger().setLevel(log_level)
    logging.info(f"Log level set to {logging.getLevelName(log_level)}")
    # Log the arguments being used
    logging.debug(f"Arguments received: {args}")

    try:
        # Paths from args are passed as strings to the constructor
        converter = ScenarioLanguageConverter(
            args.source_lang,
            args.target_lang,
            args.names_template,
            args.translations
            )

        # Input/output directories are converted to Path objects here
        input_path = pathlib.Path(args.input).resolve() # Resolve input/output paths as well
        output_path = pathlib.Path(args.output).resolve()

        logging.info(f"Resolved Input Directory: {input_path}")
        logging.info(f"Resolved Output Directory: {output_path}")


        success = converter.convert_all(
            input_path,
            output_path
        )

        return 0 if success else 1

    except (ValueError, RuntimeError, FileNotFoundError, NotADirectoryError) as e:
         logging.error(f"Error: {e}", exc_info=True if args.verbose else False)
         return 1
    except Exception as e:
         logging.error(f"An unexpected error occurred: {e}", exc_info=True if args.verbose else False)
         return 1


if __name__ == '__main__':
    sys.exit(main())
