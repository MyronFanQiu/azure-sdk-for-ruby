# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2018_08_01_7_0
  module Models
    #
    # The Azure Batch service log files upload configuration for a compute
    # node.
    #
    #
    class UploadBatchServiceLogsConfiguration

      include MsRestAzure

      # @return [String] The URL of the container within Azure Blob Storage to
      # which to upload the Batch Service log file(s). The URL must include a
      # Shared Access Signature (SAS) granting write permissions to the
      # container. The SAS duration must allow enough time for the upload to
      # finish. The start time for SAS is optional and recommended to not be
      # specified.
      attr_accessor :container_url

      # @return [DateTime] The start of the time range from which to upload
      # Batch Service log file(s). Any log file containing a log message in the
      # time range will be uploaded. This means that the operation might
      # retrieve more logs than have been requested since the entire log file
      # is always uploaded, but the operation should not retrieve fewer logs
      # than have been requested.
      attr_accessor :start_time

      # @return [DateTime] The end of the time range from which to upload Batch
      # Service log file(s). Any log file containing a log message in the time
      # range will be uploaded. This means that the operation might retrieve
      # more logs than have been requested since the entire log file is always
      # uploaded, but the operation should not retrieve fewer logs than have
      # been requested. If omitted, the default is to upload all logs available
      # after the startTime.
      attr_accessor :end_time


      #
      # Mapper for UploadBatchServiceLogsConfiguration class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'UploadBatchServiceLogsConfiguration',
          type: {
            name: 'Composite',
            class_name: 'UploadBatchServiceLogsConfiguration',
            model_properties: {
              container_url: {
                client_side_validation: true,
                required: true,
                serialized_name: 'containerUrl',
                type: {
                  name: 'String'
                }
              },
              start_time: {
                client_side_validation: true,
                required: true,
                serialized_name: 'startTime',
                type: {
                  name: 'DateTime'
                }
              },
              end_time: {
                client_side_validation: true,
                required: false,
                serialized_name: 'endTime',
                type: {
                  name: 'DateTime'
                }
              }
            }
          }
        }
      end
    end
  end
end
