import os
import logging
import argparse
from dataclasses import dataclass
from typing import Dict, Optional
from pathlib import Path


@dataclass
class ExtractConfig:
    offset0: int = 0x5a
    offset1: int = 0x2347d
    offset2: int = 0x2522d
    total_length: int = 7600 + 167559
    # Add scenario description region info
    scenario_desc_offset: int = 0x6f
    scenario_desc_length: int = 0x132
    force_desc_offset: int = 0x274
    force_desc_length: int = 0x138
    force_desc_count: int = 42
    line_break_interval: int = 0x32


class ScenarioExtractor:
    def __init__(self, output_dir: str = "./output"):
        self.output_dir = output_dir
        self._setup_logging()
        self._setup_directories()

    def _setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )

    def _setup_directories(self):
        self.wii_dir = os.path.join(self.output_dir, "Wii", "scenario")
        self.pc_dir = os.path.join(self.output_dir, "PC", "scenario")
        os.makedirs(self.wii_dir, exist_ok=True)
        os.makedirs(self.pc_dir, exist_ok=True)

    @staticmethod
    def _get_pc_filename(index_byte: int) -> str:
        index_mapping = {10: 8, 11: 9, 13: 10, 8: 11, 9: 12, 14: 13, 12: 14}
        pc_index = index_mapping.get(index_byte, index_byte)
        if pc_index < 8:
            return f"SCEN{pc_index:03d}.S11"
        else:
            return f"Scen{pc_index:03d}.s11"

    def extract_scenarios(self, input_file: str, pattern: bytes, config: ExtractConfig,
                          save_data: bool = True) -> int:
        try:
            with open(input_file, 'rb') as f:
                data = f.read()
                return self._process_data(data, pattern, config, save_data)
        except FileNotFoundError:
            logging.error(f"File {input_file} not found")
            return 0
        except Exception as e:
            logging.error(f"Error occurred: {e}")
            return 0

    def _process_data(self, data: bytes, pattern: bytes, config: ExtractConfig,
                      save_data: bool) -> int:
        occurrences = 0
        last_start = 0
        start = 0

        while True:
            start = data.find(pattern, start)
            if start == -1:
                break

            logging.info(
                f"Pattern found at offset {hex(start)}, "
                f"difference: {hex(start - last_start)}, "
                f"target length: {hex(config.total_length)}"
            )

            if save_data:
                self._save_scenario(data, start, config)

            occurrences += 1
            last_start = start
            start += config.total_length

        return occurrences

    def _insert_line_breaks(self, data: bytes, length: int, interval: int) -> bytes:
        """Insert 0x0A line breaks at specified intervals."""
        result = bytearray()
        
        # print(f"Original data: \n{data[1:].decode("shift_jisx0213")}")  # Decode for better readability
        result.append(data[0])
        for i in range(1, len(data) - 1):
            byte = data[i]
            result.append(byte)
            if byte == 0x00:
                break
            # Add line break if we're at interval and next byte isn't 0x00
            if i % interval == 0 and data[i + 1] != 0x00:
                result.append(0x0A)
                
        # Adjust to exact length
        if len(result) > length:
            return bytes(result[:length])
        elif len(result) < length:
            result.extend([0x00] * (length - len(result))) 
        # print(f"Processed data: \n{result[1:].decode("shift_jisx0213")}")  # Decode for better readability
        return bytes(result)
    
    def _save_scenario(self, data: bytes, start: int, config: ExtractConfig):
        original_index_byte = data[start + config.offset0]
        wii_filename = f"Scen{original_index_byte:03d}.s11"
        pc_filename = self._get_pc_filename(original_index_byte)

        # # Extract PC index from filename for correction
        # pc_index = int(self._get_pc_filename(original_index_byte)[4:7])

        self._write_scenario_files(
            data, start, config,
            os.path.join(self.wii_dir, wii_filename),
            os.path.join(self.pc_dir, pc_filename)
        )

    def _write_scenario_files(self, data: bytes, start: int, config: ExtractConfig,
                              wii_path: str, pc_path: str):
        try:
            # Write Wii version
            with open(wii_path, 'wb') as wii_file:
                wii_file.write(data[start: start + config.total_length])

            # Write PC version
            with open(pc_path, 'wb') as pc_file:
                # Write header with index mapping
                chunk0 = data[start: start + config.offset0]
                original_index = data[start + config.offset0]
                index_mapping = {10: 8, 11: 9, 13: 10, 8: 11, 9: 12, 14: 13, 12: 14}
                chunk0 += bytes([index_mapping.get(original_index, original_index)])
                
                # Write data up to scenario description
                pc_file.write(chunk0)
                pc_file.write(data[start + config.offset0 + 1: 
                                start + config.scenario_desc_offset])
                
                # Write scenario description with line breaks
                desc_data = data[start + config.scenario_desc_offset:
                            start + config.scenario_desc_offset + config.scenario_desc_length]
                modified_desc = self._insert_line_breaks(
                    desc_data, config.scenario_desc_length, config.line_break_interval)
                pc_file.write(modified_desc)
                

                # Write intermediate data
                pc_file.write(data[start + config.scenario_desc_offset + config.scenario_desc_length:
                                start + config.force_desc_offset])
                
                # Write force descriptions with line breaks
                for i in range(config.force_desc_count):
                    block_start = start + config.force_desc_offset + (i * config.force_desc_length)
                    block_data = data[block_start:block_start + config.force_desc_length]
                    modified_block = self._insert_line_breaks(
                        block_data, config.force_desc_length, config.line_break_interval)
                    pc_file.write(modified_block)
                
                # Write remaining data but skip officer 850-999
                remaining_start = (start + config.force_desc_offset + 
                                (config.force_desc_count * config.force_desc_length))
                pc_file.write(data[remaining_start:start + config.offset1])
                pc_file.write(data[start + config.offset2:start + config.total_length])
        except Exception as e:
            logging.error(f"Error saving files: {e}")


def main():
    # Get the script's directory and project root
    script_dir = Path(__file__).parent.resolve()
    project_root = script_dir.parent.parent

    # Default paths relative to project root
    default_input = project_root / "resources" / "san11res.bin"
    default_output = project_root / "output"

    parser = argparse.ArgumentParser(
        description='Extract Sangokushi 11 scenario files from Wii to PC format')
    parser.add_argument('-i', '--input',
                       type=str,
                       default=str(default_input),
                       help=f'Path to input san11res.bin file (default: {default_input})')
    parser.add_argument('-o', '--output',
                       type=str,
                       default=str(default_output),
                       help=f'Output directory path (default: {default_output})')

    args = parser.parse_args()

    # Convert to Path objects and resolve to absolute paths
    input_path = Path(args.input).resolve()
    output_path = Path(args.output).resolve()

    # Debug logging
    logging.info(f"Project root: {project_root}")
    logging.info(f"Looking for input file at: {input_path}")
    logging.info(f"Output will be written to: {output_path}")

    # Check if input file exists
    if not input_path.exists():
        logging.error(f"Input file not found: {input_path}")
        logging.error("Please ensure san11res.bin is in the correct location")
        return
    pattern = bytes.fromhex(
        '00 00 FE FF 16 00 00 00 4B 4F 45 49 25 53 41 4E 31 31 00 00 00 00 00 00'.replace(' ', ''))

    extractor = ScenarioExtractor(args.output)
    config = ExtractConfig()

    # Test run without saving
    occurrences = extractor.extract_scenarios(
        args.input, pattern, config, False)
    assert occurrences == 16, f"Expected 16 scenarios, found {occurrences}"

    # Actual extraction
    extractor.extract_scenarios(args.input, pattern, config, True)


if __name__ == '__main__':
    main()
