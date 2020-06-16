# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::Consumption::Mgmt::V2018_11_01_preview
  module Models
    #
    # Result of listing event summary.
    #
    class Events

      include MsRestAzure

      # @return [Array<EventSummary>] The list of event summary.
      attr_accessor :value


      #
      # Mapper for Events class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'Events',
          type: {
            name: 'Composite',
            class_name: 'Events',
            model_properties: {
              value: {
                client_side_validation: true,
                required: false,
                read_only: true,
                serialized_name: 'value',
                type: {
                  name: 'Sequence',
                  element: {
                      client_side_validation: true,
                      required: false,
                      serialized_name: 'EventSummaryElementType',
                      type: {
                        name: 'Composite',
                        class_name: 'EventSummary'
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