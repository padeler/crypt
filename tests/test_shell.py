#!/usr/bin/env python3
"""
Unit tests for the CryptShell class in crypt.py.
"""
import os
import sys
import unittest
import tempfile
import io
from unittest.mock import patch, MagicMock, mock_open

# Add parent directory to path to import crypt module
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import crypt

class TestCryptShell(unittest.TestCase):
    """Test cases for the CryptShell class."""

    def setUp(self):
        """Set up a shell instance and test data for each test."""
        self.shell = crypt.CryptShell()
        self.test_file = tempfile.NamedTemporaryFile(delete=False)
        self.test_file.close()
        self.filename = self.test_file.name
        self.test_password = "test_password"
        self.test_data = {
            "created": "2025-01-01",
            "version": crypt.VERSION,
            "iterations": crypt.DEFAULT_ITERATIONS,
            "key1": ["value1", "value2"],
            "key2": ["value3"]
        }

    def tearDown(self):
        """Clean up temporary files."""
        if os.path.exists(self.test_file.name):
            os.unlink(self.test_file.name)

    @patch('getpass.getpass')
    @patch('crypt._load_db')
    @patch('os.path.exists')
    def test_do_open(self, mock_exists, mock_load_db, mock_getpass):
        """Test opening a database file."""
        # Setup mocks
        mock_exists.return_value = True
        mock_getpass.return_value = self.test_password
        mock_load_db.return_value = self.test_data
        
        # Call the open method
        result = self.shell.do_open(self.filename)
        
        # Verify results
        self.assertIsNone(result)
        self.assertEqual(self.shell.db_dict, self.test_data)
        self.assertEqual(self.shell.password, self.test_password)
        self.assertEqual(self.shell.db_filename, self.filename)
        
        # Verify mocks were called correctly
        mock_exists.assert_called_once_with(self.filename)
        mock_getpass.assert_called_once()
        mock_load_db.assert_called_once_with(self.test_password, self.filename, crypt.LEGACY_ITERATIONS)

    @patch('crypt._write_db')
    def test_do_upgrade(self, mock_write_db):
        """Test upgrading database iterations."""
        # Setup shell with test data
        self.shell.db_dict = self.test_data.copy()
        self.shell.password = self.test_password
        self.shell.db_filename = self.filename
        
        # Set a lower iteration count
        self.shell.db_dict["iterations"] = crypt.LEGACY_ITERATIONS
        
        # Configure the mock to update the db_dict correctly
        def side_effect(password, db_dict, filename, iterations):
            # Update the iterations in the db_dict that's passed in
            db_dict["iterations"] = iterations
            
        mock_write_db.side_effect = side_effect
        
        # Call upgrade with no args (should use DEFAULT_ITERATIONS)
        result = self.shell.do_upgrade("")
        
        # Verify results
        self.assertIsNone(result)
        
        # Verify write_db was called with correct parameters
        mock_write_db.assert_called_once_with(
            self.test_password, 
            self.shell.db_dict, 
            self.filename, 
            crypt.DEFAULT_ITERATIONS
        )
        
        # Verify iterations were updated in the dict (due to our side_effect)
        self.assertEqual(self.shell.db_dict["iterations"], crypt.DEFAULT_ITERATIONS)

    @patch('crypt._write_db')
    def test_do_insert(self, mock_write_db):
        """Test inserting a new key into the database."""
        # Setup shell with test data
        self.shell.db_dict = self.test_data.copy()
        self.shell.password = self.test_password
        self.shell.db_filename = self.filename
        
        # Call insert with a new key
        result = self.shell.do_insert("new_key value1 value2 value3")
        
        # Verify results
        self.assertIsNone(result)
        self.assertEqual(self.shell.db_dict["new_key"], ["value1", "value2", "value3"])
        
        # Verify write_db was called
        mock_write_db.assert_called_once()

    @patch('crypt._write_db')
    def test_do_delete(self, mock_write_db):
        """Test deleting a key from the database."""
        # Setup shell with test data
        self.shell.db_dict = self.test_data.copy()
        self.shell.password = self.test_password
        self.shell.db_filename = self.filename
        
        # Call delete on an existing key
        result = self.shell.do_delete("key1")
        
        # Verify results
        self.assertIsNone(result)
        self.assertNotIn("key1", self.shell.db_dict)
        
        # Verify write_db was called
        mock_write_db.assert_called_once()

    def test_do_list(self):
        """Test listing keys from the database."""
        # Setup shell with test data
        self.shell.db_dict = self.test_data.copy()
        
        # Capture stdout to check output
        with patch('sys.stdout', new=io.StringIO()) as mock_stdout:
            # List all keys
            self.shell.do_list("")
            output = mock_stdout.getvalue()
            
            # Verify output contains our keys
            self.assertIn("key1", output)
            self.assertIn("key2", output)
            self.assertIn("value1", output)
            self.assertIn("value3", output)
            
        # Test listing a specific key
        with patch('sys.stdout', new=io.StringIO()) as mock_stdout:
            self.shell.do_list("key1")
            output = mock_stdout.getvalue()
            
            # Verify output contains only key1
            self.assertIn("key1", output)
            self.assertIn("value1", output)
            self.assertNotIn("key2", output)

    def test_do_generate(self):
        """Test password generation functionality."""
        # Test with default length
        with patch('sys.stdout', new=io.StringIO()) as mock_stdout:
            self.shell.do_generate("")
            output = mock_stdout.getvalue()
            
            # Verify length info is in output
            self.assertIn("length=32", output)
            
            # Extract the password from output
            import re
            match = re.search(r'Generated value \(length=32\): (.+)', output)
            password = match.group(1) if match else ""
            
            # Verify password length
            self.assertEqual(len(password), 32)
            
        # Test with custom length
        with patch('sys.stdout', new=io.StringIO()) as mock_stdout:
            self.shell.do_generate("16")
            output = mock_stdout.getvalue()
            
            # Verify length info is in output
            self.assertIn("length=16", output)
            
            # Extract the password
            match = re.search(r'Generated value \(length=16\): (.+)', output)
            password = match.group(1) if match else ""
            
            # Verify password length
            self.assertEqual(len(password), 16)

if __name__ == '__main__':
    unittest.main()