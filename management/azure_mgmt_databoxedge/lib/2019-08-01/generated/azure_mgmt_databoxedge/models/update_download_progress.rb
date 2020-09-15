# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::DataBoxEdge::Mgmt::V2019_08_01
  module Models
    #
    # Details about the download progress of update.
    #
    class UpdateDownloadProgress

      include MsRestAzure

      # @return [DownloadPhase] The download phase. Possible values include:
      # 'Unknown', 'Initializing', 'Downloading', 'Verifying'
      attr_accessor :download_phase

      # @return [Integer] Percentage of completion.
      attr_accessor :percent_complete

      # @return [Float] Total bytes to download.
      attr_accessor :total_bytes_to_download

      # @return [Float] Total bytes downloaded.
      attr_accessor :total_bytes_downloaded

      # @return [Integer] Number of updates to download.
      attr_accessor :number_of_updates_to_download

      # @return [Integer] Number of updates downloaded.
      attr_accessor :number_of_updates_downloaded


      #
      # Mapper for UpdateDownloadProgress class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'UpdateDownloadProgress',
          type: {
            name: 'Composite',
            class_name: 'UpdateDownloadProgress',
            model_properties: {
              download_phase: {
                client_side_validation: true,
                required: false,
                read_only: true,
                serialized_name: 'downloadPhase',
                type: {
                  name: 'String'
                }
              },
              percent_complete: {
                client_side_validation: true,
                required: false,
                read_only: true,
                serialized_name: 'percentComplete',
                type: {
                  name: 'Number'
                }
              },
              total_bytes_to_download: {
                client_side_validation: true,
                required: false,
                read_only: true,
                serialized_name: 'totalBytesToDownload',
                type: {
                  name: 'Double'
                }
              },
              total_bytes_downloaded: {
                client_side_validation: true,
                required: false,
                read_only: true,
                serialized_name: 'totalBytesDownloaded',
                type: {
                  name: 'Double'
                }
              },
              number_of_updates_to_download: {
                client_side_validation: true,
                required: false,
                read_only: true,
                serialized_name: 'numberOfUpdatesToDownload',
                type: {
                  name: 'Number'
                }
              },
              number_of_updates_downloaded: {
                client_side_validation: true,
                required: false,
                read_only: true,
                serialized_name: 'numberOfUpdatesDownloaded',
                type: {
                  name: 'Number'
                }
              }
            }
          }
        }
      end
    end
  end
end
