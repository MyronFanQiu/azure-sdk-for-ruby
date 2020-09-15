# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::DataBoxEdge::Mgmt::V2019_07_01
  module Models
    #
    # Fields for tracking refresh job on the share.
    #
    class RefreshDetails

      include MsRestAzure

      # @return [String] If a refresh share job is currently in progress on
      # this share, this field indicates the ARM resource ID of that job. The
      # field is empty if no job is in progress.
      attr_accessor :in_progress_refresh_job_id

      # @return [DateTime] Indicates the completed time for the last refresh
      # job on this particular share, if any.This could be a failed job or a
      # successful job.
      attr_accessor :last_completed_refresh_job_time_in_utc

      # @return [String] Indicates the relative path of the error xml for the
      # last refresh job on this particular share, if any. This could be a
      # failed job or a successful job.
      attr_accessor :error_manifest_file

      # @return [String] Indicates the id of the last refresh job on this
      # particular share,if any. This could be a failed job or a successful
      # job.
      attr_accessor :last_job


      #
      # Mapper for RefreshDetails class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'RefreshDetails',
          type: {
            name: 'Composite',
            class_name: 'RefreshDetails',
            model_properties: {
              in_progress_refresh_job_id: {
                client_side_validation: true,
                required: false,
                serialized_name: 'inProgressRefreshJobId',
                type: {
                  name: 'String'
                }
              },
              last_completed_refresh_job_time_in_utc: {
                client_side_validation: true,
                required: false,
                serialized_name: 'lastCompletedRefreshJobTimeInUTC',
                type: {
                  name: 'DateTime'
                }
              },
              error_manifest_file: {
                client_side_validation: true,
                required: false,
                serialized_name: 'errorManifestFile',
                type: {
                  name: 'String'
                }
              },
              last_job: {
                client_side_validation: true,
                required: false,
                serialized_name: 'lastJob',
                type: {
                  name: 'String'
                }
              }
            }
          }
        }
      end
    end
  end
end
