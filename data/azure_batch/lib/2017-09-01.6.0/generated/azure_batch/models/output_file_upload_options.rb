# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2017_09_01_6_0
  module Models
    #
    # Details about an output file upload operation, including under what
    # conditions to perform the upload.
    #
    #
    class OutputFileUploadOptions

      include MsRestAzure

      # @return [OutputFileUploadCondition] The conditions under which the task
      # output file or set of files should be uploaded. The default is
      # taskcompletion. Possible values include: 'taskSuccess', 'taskFailure',
      # 'taskCompletion'
      attr_accessor :upload_condition


      #
      # Mapper for OutputFileUploadOptions class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'OutputFileUploadOptions',
          type: {
            name: 'Composite',
            class_name: 'OutputFileUploadOptions',
            model_properties: {
              upload_condition: {
                client_side_validation: true,
                required: true,
                serialized_name: 'uploadCondition',
                type: {
                  name: 'Enum',
                  module: 'OutputFileUploadCondition'
                }
              }
            }
          }
        }
      end
    end
  end
end
