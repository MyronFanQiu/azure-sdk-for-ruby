# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2019_06_01_9_0
  module Models
    #
    # A specification for uploading files from an Azure Batch Compute Node to
    # another location after the Batch service has finished executing the Task
    # process.
    #
    #
    class OutputFile

      include MsRestAzure

      # @return [String] A pattern indicating which file(s) to upload. Both
      # relative and absolute paths are supported. Relative paths are relative
      # to the Task working directory. The following wildcards are supported: *
      # matches 0 or more characters (for example pattern abc* would match abc
      # or abcdef), ** matches any directory, ? matches any single character,
      # [abc] matches one character in the brackets, and [a-c] matches one
      # character in the range. Brackets can include a negation to match any
      # character not specified (for example [!abc] matches any character but
      # a, b, or c). If a file name starts with "." it is ignored by default
      # but may be matched by specifying it explicitly (for example *.gif will
      # not match .a.gif, but .*.gif will). A simple example: **\*.txt matches
      # any file that does not start in '.' and ends with .txt in the Task
      # working directory or any subdirectory. If the filename contains a
      # wildcard character it can be escaped using brackets (for example abc[*]
      # would match a file named abc*). Note that both \ and / are treated as
      # directory separators on Windows, but only / is on Linux. Environment
      # variables (%var% on Windows or $var on Linux) are expanded prior to the
      # pattern being applied.
      attr_accessor :file_pattern

      # @return [OutputFileDestination] The destination for the output file(s).
      attr_accessor :destination

      # @return [OutputFileUploadOptions] Additional options for the upload
      # operation, including under what conditions to perform the upload.
      attr_accessor :upload_options


      #
      # Mapper for OutputFile class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'OutputFile',
          type: {
            name: 'Composite',
            class_name: 'OutputFile',
            model_properties: {
              file_pattern: {
                client_side_validation: true,
                required: true,
                serialized_name: 'filePattern',
                type: {
                  name: 'String'
                }
              },
              destination: {
                client_side_validation: true,
                required: true,
                serialized_name: 'destination',
                type: {
                  name: 'Composite',
                  class_name: 'OutputFileDestination'
                }
              },
              upload_options: {
                client_side_validation: true,
                required: true,
                serialized_name: 'uploadOptions',
                type: {
                  name: 'Composite',
                  class_name: 'OutputFileUploadOptions'
                }
              }
            }
          }
        }
      end
    end
  end
end
