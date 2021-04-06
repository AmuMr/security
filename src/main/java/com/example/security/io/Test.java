package com.example.security.io;


public class Test {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		String fileName = "/Users/sky/Downloads/test.txt";
		int lineNum = 10*1024;
		
		/*FileWriteDemo fileWriterDemo = new FileWriterDemo(fileName, lineNum);
		fileWriterDemo.write();
		
		System.out.println();
		
		FileWriteDemo bufferedWriterDemo = new BufferedWriterDemo(fileName, lineNum);
		bufferedWriterDemo.write();
		
		System.out.println();
		
		FileWriteDemo fileOutputStreamDemo = new FileOutputStreamDemo(fileName, lineNum);
		fileOutputStreamDemo.write();
		
		System.out.println();
		
		FileWriteDemo bufferedOutputStreamDemo = new BufferedOutputStreamDemo(fileName, lineNum);
		bufferedOutputStreamDemo.write();
		
		System.out.println();*/
		
		FileWriteDemo fileChannelDemo = new FileChannelDemo(fileName, lineNum);
		fileChannelDemo.write();

	}

}
