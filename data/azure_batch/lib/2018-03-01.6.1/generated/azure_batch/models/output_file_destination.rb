# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2018_03_01_6_1
  module Models
    #
    # The destination to which a file should be uploaded.
    #
    #
    class OutputFileDestination

      include MsRestAzure

      # @return [OutputFileBlobContainerDestination] A location in Azure blob
      # storage to which files are uploaded.
      attr_accessor :container


      #
      # Mapper for OutputFileDestination class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'OutputFileDestination',
          type: {
            name: 'Composite',
            class_name: 'OutputFileDestination',
            model_properties: {
              container: {
                client_side_validation: true,
                required: false,
                serialized_name: 'container',
                type: {
                  name: 'Composite',
                  class_name: 'OutputFileBlobContainerDestination'
                }
              }
            }
          }
        }
      end
    end
  end
end
