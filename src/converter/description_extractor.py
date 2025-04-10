import json
import logging
import re
from pathlib import Path
from dataclasses import dataclass
from typing import Dict, Optional
import argparse
import sys
# from .language_config import LANGUAGE_CONFIGS, LanguageConfig


@dataclass
class LanguageConfig:
    title_offset: int
    title_length: int
    description_offset: int
    description_length: int
    faction_description_offset: int
    faction_description_length: int
    encoding: str

    @classmethod
    def get_config(cls, language: str) -> Optional['LanguageConfig']:
        configs = {
            "jap": cls(
                title_offset=0x5e,
                title_length=0x10,
                description_offset=0x6f,
                description_length=0x132,
                faction_description_offset=0x274,
                faction_description_length=0x138,
                encoding="shift_jisx0213"
            ),
            "cht": cls(
                title_offset=0x5e,
                title_length=0x10,
                description_offset=0x6f,
                description_length=0x16b,
                faction_description_offset=0x2ad,
                faction_description_length=0x171,
                encoding="big5"
            )
        }
        return configs.get(language)


class ScenarioDescriptionExtractor:
    SCENARIO_FILE_PATTERN = re.compile(r"(?i)^scen\d{3}\.s11$")
    FACTION_COUNT = 42

    def __init__(self, config: LanguageConfig):
        self.config = config
        self._setup_logging()

    def _setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def read_text(self, file_path: Path, offset: int, length: int) -> str:
        """Read and decode text from file at specified offset."""
        try:
            with open(file_path, "rb") as f:
                f.seek(offset)
                raw_data = f.read(length)
                return raw_data[1:].rstrip(b'\x00').decode(self.config.encoding).strip()
        except UnicodeDecodeError:
            logging.error(
                f"Failed to decode text at offset {hex(offset)} in {file_path}")
            return ""
        except Exception as e:
            logging.error(f"Error reading file {file_path}: {e}")
            return ""

    def extract_scenario_data(self, file_path: Path) -> Dict:
        """Extract title, description and faction descriptions from scenario file."""
        if not file_path.is_file():
            raise FileNotFoundError(f"Scenario file not found: {file_path}")

        scenario_data: dict[str, str | list[str]] = {
            "title": self.read_text(file_path, self.config.title_offset, self.config.title_length),
            "description": self.read_text(file_path, self.config.description_offset, self.config.description_length),
            "factions": []
        }

        # Extract faction descriptions
        for i in range(self.FACTION_COUNT):
            offset = self.config.faction_description_offset + \
                (i * self.config.faction_description_length)
            faction_desc = self.read_text(
                file_path, offset, self.config.faction_description_length)
            if faction_desc:
                scenario_data["factions"].append(faction_desc)
            else:
                break

        return scenario_data

    def process_directory(self, input_dir: Path, output_path: Path) -> bool:
        """Process all scenario files in directory."""
        # Verify input directory exists and contains .s11 files
        if not input_dir.is_dir():
            logging.error(f"Input directory not found: {input_dir}")
            return False

        s11_files = list(input_dir.glob("*.s11"))
        if not s11_files:
            logging.error(f"No .s11 files found in {input_dir}")
            return False

        # Create output directory if needed
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Process valid scenario files
        scenarios = {}
        for file_path in s11_files:
            if self.SCENARIO_FILE_PATTERN.match(file_path.name):
                try:
                    logging.info(f"Processing {file_path.name}")
                    scenarios[file_path.name] = self.extract_scenario_data(
                        file_path)
                except Exception as e:
                    logging.error(f"Failed to process {file_path.name}: {e}")

        if not scenarios:
            logging.error("No valid scenario files were processed")
            return False

        # Save results
        try:
            # Save JSON
            with open(output_path.with_suffix('.json'), "w", encoding="utf-8") as f:
                json.dump(scenarios, f, ensure_ascii=False, indent=4)

            # Save text
            with open(output_path.with_suffix('.txt'), "w", encoding=self.config.encoding) as f:
                for scen_name, data in scenarios.items():
                    f.write(f"[Scenario] {scen_name}\n")
                    f.write(f"Title: {data['title']}\n")
                    f.write(f"Description:\n{data['description']}\n\n")
                    f.write("Factions:\n")
                    for idx, faction in enumerate(data['factions'], 1):
                        f.write(f"{idx:02d}: {faction}\n")
                    f.write("\n" + "="*50 + "\n\n")

            logging.info(
                f"Successfully saved output to {output_path}.json/.txt")
            return True

        except Exception as e:
            logging.error(f"Failed to save output: {e}")
            return False

    def _prepare_text_block(self, text: str, total_length: int, preserve_first_byte: bytes = None) -> bytes:
        """Prepare text block with encoding and padding"""
        try:
            # Encode text
            encoded = text.encode(self.config.encoding)
            
            # Calculate content length (total - 1 if preserving first byte)
            content_length = total_length - 1 if preserve_first_byte else total_length
            
            # Truncate or pad content
            if len(encoded) > content_length:
                encoded = encoded[:content_length]
            else:
                encoded = encoded.ljust(content_length, b'\x00')
                
            # Add preserved byte if needed
            if preserve_first_byte:
                encoded = preserve_first_byte + encoded
                
            return encoded
            
        except UnicodeEncodeError as e:
            logging.error(f"Failed to encode text: {e}")
            raise

    def write_scenario_data(self, file_path: Path, scenario_data: Dict) -> bool:
        """Write descriptions back to scenario file."""
        try:
            # Read entire file first
            with open(file_path, "rb") as f:
                data = bytearray(f.read())

            # Write title
            first_byte = data[self.config.title_offset:self.config.title_offset + 1]
            title_block = self._prepare_text_block(
                scenario_data['title'], 
                self.config.title_length,
                first_byte
            )
            data[self.config.title_offset:self.config.title_offset + self.config.title_length] = title_block

            # Write scenario description
            first_byte = data[self.config.description_offset:self.config.description_offset + 1]
            desc_block = self._prepare_text_block(
                scenario_data['description'],
                self.config.description_length,
                first_byte
            )
            data[self.config.description_offset:self.config.description_offset + self.config.description_length] = desc_block

            # Write faction descriptions
            for i, faction in enumerate(scenario_data['factions']):
                if i >= self.FACTION_COUNT:
                    break
                    
                offset = self.config.faction_description_offset + (i * self.config.faction_description_length)
                first_byte = data[offset:offset + 1]
                
                faction_block = self._prepare_text_block(
                    faction,
                    self.config.faction_description_length,
                    first_byte
                )
                data[offset:offset + self.config.faction_description_length] = faction_block

            # Write back to file
            with open(file_path, "wb") as f:
                f.write(data)

            logging.info(f"Successfully updated {file_path.name}")
            return True

        except Exception as e:
            logging.error(f"Failed to update {file_path.name}: {e}")
            return False
    def apply_edited_descriptions(self, scenarios_dir: Path, json_path: Path) -> bool:
        """Apply edited descriptions from JSON file to scenario files."""
        try:
            # Load edited descriptions
            with open(json_path, encoding='utf-8') as f:
                edited_data = json.load(f)

            if not edited_data:
                logging.error("No data found in JSON file")
                return False

            success_count = 0
            for filename, scenario_data in edited_data.items():
                scen_path = scenarios_dir / filename
                if not scen_path.exists():
                    logging.error(f"Scenario file not found: {filename}")
                    continue

                if self.write_scenario_data(scen_path, scenario_data):
                    success_count += 1

            logging.info(
                f"Successfully updated {success_count} scenario files")
            return success_count > 0

        except Exception as e:
            logging.error(f"Failed to apply descriptions: {e}")
            return False

    def test_write_back(self, file_path: Path, temp_dir: Optional[Path] = None) -> bool:
        """Test description extraction and write-back by comparing original and modified files."""
        try:
            # Use system temp dir if none provided
            if temp_dir is None:
                temp_dir = Path(os.getenv('TEMP', './temp'))
            temp_dir.mkdir(parents=True, exist_ok=True)

            # Create temp copy
            test_file = temp_dir / f"test_{file_path.name}"
            import shutil
            shutil.copy2(file_path, test_file)

            # Extract data
            original_data = self.extract_scenario_data(file_path)

            # Write back to temp file
            self.write_scenario_data(test_file, original_data)

            # Extract from modified file
            modified_data = self.extract_scenario_data(test_file)

            # Compare results
            if original_data == modified_data:
                logging.info(
                    f"Test passed for {file_path.name} - write-back successful")
                return True
            else:
                logging.error(
                    f"Test failed for {file_path.name} - data mismatch")
                # Log differences
                for key in ['title', 'description']:
                    if original_data[key] != modified_data[key]:
                        logging.error(f"{key} mismatch:")
                        logging.error(f"Original: {original_data[key]}")
                        logging.error(f"Modified: {modified_data[key]}")

                if len(original_data['factions']) != len(modified_data['factions']):
                    logging.error("Faction count mismatch")
                else:
                    for i, (orig, mod) in enumerate(zip(original_data['factions'], modified_data['factions'])):
                        if orig != mod:
                            logging.error(f"Faction {i+1} mismatch:")
                            logging.error(f"Original: {orig}")
                            logging.error(f"Modified: {mod}")
                return False

        except Exception as e:
            logging.error(f"Test failed with error: {e}")
            return False
        finally:
            # Cleanup
            if test_file.exists():
                test_file.unlink()


def main():
    parser = argparse.ArgumentParser(
        description='Extract/Write descriptions for Sangokushi XI scenario files')
    parser.add_argument('-i', '--input', required=True,
                        help='Input directory with .s11 files')
    parser.add_argument('-o', '--output', required=True,
                        help='Output file path (without extension)')
    parser.add_argument(
        '-l', '--language', choices=['jap', 'cht'], required=True, help='Language version')
    parser.add_argument('-t', '--test', action='store_true',
                        help='Run write-back test on input files')
    parser.add_argument('-w', '--write', action='store_true',
                        help='Write mode - apply JSON descriptions to scenario files')
    parser.add_argument(
        '--temp-dir', help='Custom temp directory for testing', default=None)

    args = parser.parse_args()

    config = LanguageConfig.get_config(args.language)
    if not config:
        logging.error(f"Unsupported language: {args.language}")
        return 1

    extractor = ScenarioDescriptionExtractor(config)

    if args.test:
        # Test mode - verify write-back functionality
        input_dir = Path(args.input)
        temp_dir = Path(args.temp_dir) if args.temp_dir else None

        if not input_dir.is_dir():
            logging.error(f"Input directory not found: {input_dir}")
            return 1

        success = True
        for file_path in input_dir.glob("*.s11"):
            if extractor.SCENARIO_FILE_PATTERN.match(file_path.name):
                if not extractor.test_write_back(file_path, temp_dir):
                    success = False
    elif args.write:
        # Write mode - apply edited descriptions to scenario files
        success = extractor.apply_edited_descriptions(
            Path(args.input), Path(args.output))
    else:
        # Normal extraction mode
        success = extractor.process_directory(
            Path(args.input), Path(args.output))
    return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())
