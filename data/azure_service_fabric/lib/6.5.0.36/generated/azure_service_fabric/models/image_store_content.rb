# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::ServiceFabric::V6_5_0_36
  module Models
    #
    # Information about the image store content.
    #
    class ImageStoreContent

      include MsRestAzure

      # @return [Array<FileInfo>] The list of image store file info objects
      # represents files found under the given image store relative path.
      attr_accessor :store_files

      # @return [Array<FolderInfo>] The list of image store folder info objects
      # represents subfolders found under the given image store relative path.
      attr_accessor :store_folders


      #
      # Mapper for ImageStoreContent class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'ImageStoreContent',
          type: {
            name: 'Composite',
            class_name: 'ImageStoreContent',
            model_properties: {
              store_files: {
                client_side_validation: true,
                required: false,
                serialized_name: 'StoreFiles',
                type: {
                  name: 'Sequence',
                  element: {
                      client_side_validation: true,
                      required: false,
                      serialized_name: 'FileInfoElementType',
                      type: {
                        name: 'Composite',
                        class_name: 'FileInfo'
                      }
                  }
                }
              },
              store_folders: {
                client_side_validation: true,
                required: false,
                serialized_name: 'StoreFolders',
                type: {
                  name: 'Sequence',
                  element: {
                      client_side_validation: true,
                      required: false,
                      serialized_name: 'FolderInfoElementType',
                      type: {
                        name: 'Composite',
                        class_name: 'FolderInfo'
                      }
                  }
                }
              }
            }
          }
        }
      end
    end
  end
end
