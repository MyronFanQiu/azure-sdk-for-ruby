# encoding: utf-8
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.

module Azure::CognitiveServices::WebSearch::V1_0
  module Models
    #
    # Model object.
    #
    #
    class WebWebGrouping

      include MsRestAzure

      @@discriminatorMap = Hash.new

      def initialize
        @_type = "Web/WebGrouping"
      end

      attr_accessor :_type

      # @return [Array<WebPage>]
      attr_accessor :web_pages


      #
      # Mapper for WebWebGrouping class as Ruby Hash.
      # This will be used for serialization/deserialization.
      #
      def self.mapper()
        {
          client_side_validation: true,
          required: false,
          serialized_name: 'Web/WebGrouping',
          type: {
            name: 'Composite',
            polymorphic_discriminator: '_type',
            uber_parent: 'WebWebGrouping',
            class_name: 'WebWebGrouping',
            model_properties: {
              web_pages: {
                client_side_validation: true,
                required: true,
                serialized_name: 'webPages',
                type: {
                  name: 'Sequence',
                  element: {
                      client_side_validation: true,
                      required: false,
                      serialized_name: 'WebPageElementType',
                      type: {
                        name: 'Composite',
                        class_name: 'WebPage'
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
