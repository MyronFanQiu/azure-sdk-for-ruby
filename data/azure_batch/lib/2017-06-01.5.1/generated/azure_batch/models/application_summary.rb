# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Batch::V2017_06_01_5_1
  module Models
    #
    # Contains information about an application in an Azure Batch account.
    #
    #
    class ApplicationSummary

      include MsRestAzure

      # @return [String] A string that uniquely identifies the application
      # within the account.
      attr_accessor :id

      # @return [String] The display name for the application.
      attr_accessor :display_name

      # @return [Array<String>] The list of available versions of the
      # application.
      attr_accessor :versions


      #
      # Mapper for ApplicationSummary class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'ApplicationSummary',
          type: {
            name: 'Composite',
            class_name: 'ApplicationSummary',
            model_properties: {
              id: {
                client_side_validation: true,
                required: true,
                serialized_name: 'id',
                type: {
                  name: 'String'
                }
              },
              display_name: {
                client_side_validation: true,
                required: true,
                serialized_name: 'displayName',
                type: {
                  name: 'String'
                }
              },
              versions: {
                client_side_validation: true,
                required: true,
                serialized_name: 'versions',
                type: {
                  name: 'Sequence',
                  element: {
                      client_side_validation: true,
                      required: false,
                      serialized_name: 'StringElementType',
                      type: {
                        name: 'String'
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